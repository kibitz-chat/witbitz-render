// agent/ledgerSegments.mjs — a room's ledger stored in SEGMENTS (v4), so an append writes one small object instead of the
// whole history (docs/ledger-segments.md; measured 2026-10-05: 4.7 GB of superseded versions for 144 MB of live ledgers,
// 42 KB written per append on average, up to 11 MB).
//
//   memory/_ledger/<room>.json            HEADER   { v:4, gen, segs }                      — the room's ledger key, as before
//   memory/_lseg_<gen>_<i>/<room>.json    SEGMENT  { v:4, i, from, boxes:[…], done? }      — `done` lives on the TAIL
//
// The boxes are byte-identical to v3's and keep their ABSOLUTE index (the AAD binds a box to it), so readers hand callers
// the same v3 shape { v:3, boxes, done } and no client ever sees v4. Keys end in `<room>.json`, so room purge, account
// erase and the bucket lifecycle cover segments unchanged.
//
// CONCURRENCY. A layout is a GENERATION (`gen`, random): converting a v3 room or rebuilding a ledger writes a whole new
// generation, then switches the header with compare-and-set — two writers never touch each other's segments, and a
// loser's generation is simply never referenced. Within a generation the TAIL is the commit point: an append is a CAS on
// the tail; opening the next segment is create-if-absent (exactly one writer wins). The header's `segs` is a HINT, bumped
// best-effort after a new segment — readers probe forward past it, so a crash between the two loses nothing.
//
// Pure apart from `io`: { read(key) → { body, etag } (absent: body null), writeIf(key, body, etag|null) → bool
// (null = create only if absent), head?(key) → etag | null, headerKey, segKey(gen, i) }.

export const SEG_BOXES = 64
export const SEG_BYTES = 256_000
export const LEDGER_V4 = 4

export const isV4Header = (p) => !!p && typeof p === 'object' && p.v === LEDGER_V4 && typeof p.gen === 'string' && Number.isInteger(p.segs) && !Array.isArray(p.boxes)
export function parseV4Header (body) {
  if (typeof body !== 'string' || body.length > 4096 || !body.includes('"gen"')) return null
  try { const p = JSON.parse(body); return isV4Header(p) ? p : null } catch { return null }
}
export const newGen = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4)
const boxBytes = (b) => String(b).length + 3

/** Split boxes into segments: at most SEG_BOXES each and SEG_BYTES each (never fewer than one box). */
export function splitBoxes (boxes) {
  const out = []; let cur = [], bytes = 0
  for (const b of boxes) {
    const n = boxBytes(b)
    if (cur.length && (cur.length >= SEG_BOXES || bytes + n > SEG_BYTES)) { out.push(cur); cur = []; bytes = 0 }
    cur.push(b); bytes += n
  }
  if (cur.length) out.push(cur)
  return out
}
const fits = (seg, add) => seg.boxes.length === 0 || (seg.boxes.length + add.length <= SEG_BOXES && seg.boxes.concat(add).reduce((s, b) => s + boxBytes(b), 0) <= SEG_BYTES)

function parseSeg (body, i) {
  let s = null; try { s = JSON.parse(body) } catch { s = null }
  if (!s || s.v !== LEDGER_V4 || s.i !== i || !Number.isInteger(s.from) || !Array.isArray(s.boxes)) throw new Error(`segment ${i} is malformed`)
  return s
}

/** Every box, in order → { boxes, done, tail: { i, etag, seg } }. A segment missing BELOW the last one is a broken ledger
 *  and THROWS — a reader must never present a hole as a shorter room. */
export async function readAllSegments (io, header) {
  const known = Math.max(1, header.segs)
  const reads = await Promise.all(Array.from({ length: known }, (_, i) => io.read(io.segKey(header.gen, i))))
  const segs = []
  for (let i = 0; i < known; i++) {
    if (reads[i].body == null) { if (i === 0 && header.segs === 0) break; throw new Error(`segment ${i} of ${header.segs} is missing`) }
    segs.push({ i, etag: reads[i].etag, seg: parseSeg(reads[i].body, i) })
  }
  for (let i = segs.length; ; i++) { // the header's count is a hint: probe forward
    const r = await io.read(io.segKey(header.gen, i)); if (r.body == null) break
    segs.push({ i, etag: r.etag, seg: parseSeg(r.body, i) })
  }
  const boxes = []
  for (const s of segs) { if (s.seg.from !== boxes.length) throw new Error(`segment ${s.i} starts at ${s.seg.from}, expected ${boxes.length}`); boxes.push(...s.seg.boxes) }
  const tail = segs.length ? segs[segs.length - 1] : null
  return { boxes, done: tail && Number.isInteger(tail.seg.done) ? tail.seg.done : undefined, tail }
}

/** The tail alone (no history read) → { i, etag, seg } | null for an empty generation. */
export async function readTail (io, header) {
  let i = Math.max(0, header.segs - 1)
  let r = await io.read(io.segKey(header.gen, i))
  if (r.body == null) { if (i === 0) return null; throw new Error(`segment ${i} of ${header.segs} is missing`) }
  let cur = { i, etag: r.etag, seg: parseSeg(r.body, i) }
  for (;;) {
    r = await io.read(io.segKey(header.gen, cur.i + 1)); if (r.body == null) return cur
    cur = { i: cur.i + 1, etag: r.etag, seg: parseSeg(r.body, cur.i + 1) }
  }
}

/** The poll's change tag: the header's ETag + the tail's index and ETag (an append changes only the tail). */
export async function tailTag (io, headerEtag, header) {
  let i = Math.max(0, header.segs - 1)
  let t = await io.head(io.segKey(header.gen, i))
  if (t == null) return i === 0 ? `${headerEtag}.0.empty` : null
  for (;;) { const n = await io.head(io.segKey(header.gen, i + 1)); if (n == null) break; i++; t = n }
  return `${headerEtag}.${i}.${t}`
}
export const tagFromTail = (headerEtag, tail) => (tail ? `${headerEtag}.${tail.i}.${tail.etag}` : `${headerEtag}.0.empty`)

/** Write `boxes` as a NEW generation (create-only segments) → the header to CAS into place. */
export async function writeGeneration (io, boxes, done) {
  const gen = newGen(), parts = splitBoxes(boxes)
  let from = 0
  for (let i = 0; i < parts.length; i++) {
    const last = i === parts.length - 1
    const ok = await io.writeIf(io.segKey(gen, i), JSON.stringify({ v: LEDGER_V4, i, from, boxes: parts[i], ...(last && Number.isInteger(done) ? { done } : {}) }), null)
    if (!ok) throw new Error(`segment ${i} of a fresh generation already existed`)
    from += parts[i].length
  }
  return { v: LEDGER_V4, gen, segs: parts.length }
}

/** ONE append attempt on a v4 ledger. `seal(entry, index)` → box. → { ok:true, count } | { ok:false, reason:'conflict'|'stale', count? }.
 *  `done`: 'all' | integer | undefined (carried), monotonic, as appendLedger documents. */
export async function appendOnce (io, header, headerEtag, add, { seal, done, expectCount } = {}) {
  const tail = await readTail(io, header)
  const count = tail ? tail.seg.from + tail.seg.boxes.length : 0
  if (Number.isInteger(expectCount) && count !== expectCount) return { ok: false, reason: 'stale', count }
  const prevDone = tail && Number.isInteger(tail.seg.done) ? tail.seg.done : undefined
  const total = count + add.length
  let nextDone = done === 'all' ? total : Number.isInteger(done) ? Math.min(done, total) : prevDone
  if (Number.isInteger(nextDone) && Number.isInteger(prevDone) && nextDone < prevDone) nextDone = prevDone
  if (!add.length && nextDone === prevDone) return { ok: true, count }
  const boxes = []
  for (let j = 0; j < add.length; j++) { const b = await seal(add[j], count + j); if (b == null) throw new Error('seal_failed'); boxes.push(b) }
  const withDone = (o) => (Number.isInteger(nextDone) ? { ...o, done: nextDone } : o)
  if (!tail) {
    const ok = await io.writeIf(io.segKey(header.gen, 0), JSON.stringify(withDone({ v: LEDGER_V4, i: 0, from: 0, boxes })), null)
    return ok ? { ok: true, count: total } : { ok: false, reason: 'conflict' }
  }
  if (fits(tail.seg, boxes)) {
    const { done: _d, ...rest } = tail.seg
    const ok = await io.writeIf(io.segKey(header.gen, tail.i), JSON.stringify(withDone({ ...rest, boxes: tail.seg.boxes.concat(boxes) })), tail.etag)
    return ok ? { ok: true, count: total } : { ok: false, reason: 'conflict' }
  }
  const i = tail.i + 1
  const ok = await io.writeIf(io.segKey(header.gen, i), JSON.stringify(withDone({ v: LEDGER_V4, i, from: count, boxes })), null)
  if (!ok) return { ok: false, reason: 'conflict' }
  try { await io.writeIf(io.headerKey, JSON.stringify({ ...header, segs: i + 1 }), headerEtag) } catch { /* a hint — readers probe forward */ }
  return { ok: true, count: total }
}

/** Rewrite boxes in place, segment by segment (CAS per segment). `replace(box, index)` → a new box, or null to keep it.
 *  → the number of boxes rewritten. */
export async function rewriteSegments (io, header, replace, { tries = 8 } = {}) {
  let n = 0
  for (let i = 0; ; i++) {
    let done = false
    for (let attempt = 0; attempt < tries && !done; attempt++) {
      const r = await io.read(io.segKey(header.gen, i))
      if (r.body == null) return n
      const seg = parseSeg(r.body, i)
      const boxes = seg.boxes.slice(); let k = 0
      for (let j = 0; j < boxes.length; j++) { const nb = await replace(boxes[j], seg.from + j); if (nb != null) { boxes[j] = nb; k++ } }
      if (!k) { done = true; break }
      if (await io.writeIf(io.segKey(header.gen, i), JSON.stringify({ ...seg, boxes }), r.etag)) { n += k; done = true }
    }
    if (!done) return n
  }
}

/** Move the header's ETag after an in-place edit (a CAS bump of `rev`). The poll tag names the header and the tail, so an
 *  edit in an EARLIER segment would otherwise read as "unchanged" — and a peer refreshes reactions only on "changed,
 *  nothing new" (ledgerView.needsTailResync). → true when bumped. */
export async function touchHeader (io, { tries = 5 } = {}) {
  for (let i = 0; i < tries; i++) {
    const r = await io.read(io.headerKey)
    const h = parseV4Header(r.body); if (!h) return false
    if (await io.writeIf(io.headerKey, JSON.stringify({ ...h, rev: (Number(h.rev) || 0) + 1 }), r.etag)) return true
  }
  return false
}
