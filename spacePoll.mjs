// M2 Cut 3 (poll-while-open) — the READ side of an async Space (docs/async-spaces-m2.md).
//
// The SEALED BLOB NEVER LEAVES THE SERVER. All processing is in the Lambda (the transient render): the client sends
// `mk` for its active window, the Lambda opens the sealed ledger, returns only the NEW entries as PLAINTEXT, and drops
// `mk`. The client is thin — it sends turns and receives rendered turns, and never handles ciphertext or the crypto.
// This keeps the encrypted data + the inference (Bedrock) inside the AWS boundary (data gravity), and matches Cut 2's
// handleSpaceTurn (which likewise decrypts in the Lambda and returns only the reply).
//
// Cheap unchanged-check WITHOUT decrypting: an etag = hash of the *ciphertext* (changes on every write, reveals only
// "changed", never the count). The client sends its last etag; if it matches, we return no entries and NEVER decrypt
// (mk unused). Only a real change costs a decrypt. NOTE the deferred gap: an AWAY member whose app is CLOSED isn't
// reached until they reopen it (polling needs a running app). Poll ONLY while the Space is open on screen — background/
// idle polling breaks idle-≈-$0 (async-rooms-cost.md) and the OS throttles it anyway.
import { webcrypto as crypto } from 'crypto'
import { setRoomKey } from './roomKey.mjs'
import { getLedgerRawV, getLedgerTag, getLedger, getPartialRaw, getDeviceCallRaw, getNotifRaw } from './sessionStore.mjs'

/** The in-progress reply and the turn's progress, both sealed and passed through verbatim. `partial` carries TEXT only —
 *  a client that predates the progress line reads exactly what it always did — and `partialStatus` rides beside it,
 *  even before the first word exists (docs/turn-progress.md). */
export const STATUS_STALE_MS = 45_000 // the turn rewrites its record every 10 s while it runs (asyncTurn heartbeat)
export function withTurnProgress(o, partial, now = Date.now()) {
  if (!partial) return o
  // A record older than the heartbeat allows belongs to a turn that DIED without clearing (a worker killed at its time
  // limit, a crash) — its status AND its frozen text. The owner, 2026-09-30: a long answer killed mid-stream sat on
  // screen as a "short answer" until the next turn replaced it. A live turn rewrites the record at least every 10 s.
  if (partial.at && now - partial.at > STATUS_STALE_MS) return o
  if (!partial.box && !partial.status) return o
  return { ...o, ...(partial.box ? { partial: partial.box } : {}), partialSeq: partial.seq, ...(partial.status ? { partialStatus: partial.status } : {}) }
}
import { sliceRawV3, isV3 } from './spaceLedgerV3.mjs'

const enc = new TextEncoder()
const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** etag = a hash of the SEALED blob (ciphertext) — the cheap change-tag. Computed WITHOUT decrypting; reveals only
 *  "changed", not the turn count. Deterministic per stored blob → an unchanged ledger yields a stable etag. */
export async function etagOf(sealed) {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(sealed)))).slice(0, 22)
}

// ★ AN UNCHANGED POLL READS NOTHING (2026-10-05). Hashing the ciphertext meant every poll downloaded the WHOLE ledger to
// answer "no change" — an idle poll on an 8 MB room moved 8 MB. On S3 the object's own ETag (which changes on every write)
// answers that from a HEAD, and the etag a changed poll hands out is that same ETag. 'o' + its hex can never equal a
// 22-char sha etag, so a client holding an old one just gets one changed poll, sliced from its own count. Stores with no
// cheap tag (the enclave's parent, a local dir) answer null and keep sha256(body), byte-for-byte as before.
export const tagEtag = (tag) => 'o' + String(tag).replace(/[^A-Za-z0-9-]/g, '')
// The ledger readers a poll uses. A caller that injects only `getRaw` (the asleep relay, older tests) gets no tag.
function ledgerReaders(deps) {
  if (deps.getRawV || deps.getTag) return { getRawV: deps.getRawV || getLedgerRawV, getTag: deps.getTag || (async () => null) }
  if (deps.getRaw) return { getRawV: async (room) => ({ body: await deps.getRaw(room), tag: null }), getTag: async () => null }
  return { getRawV: getLedgerRawV, getTag: getLedgerTag }
}
/** → { unchanged: etag } when the tag alone proves `sinceEtag` current, else { sealed, etag } (sealed null = no ledger). */
async function readLedgerForPoll(room, sinceEtag, deps) {
  const { getRawV, getTag } = ledgerReaders(deps)
  if (sinceEtag && sinceEtag[0] === 'o') {
    const tag = await getTag(room).catch(() => null)
    if (tag && tagEtag(tag) === sinceEtag) return { unchanged: sinceEtag }
  }
  const v = (await getRawV(room).catch(() => null)) || {}
  if (v.body == null) return { sealed: null }
  return { sealed: v.body, etag: v.tag ? tagEtag(v.tag) : await etagOf(v.body) }
}

/** Poll a Space, PROCESSED IN THE LAMBDA. The blob is never returned — only plaintext entries the Lambda decrypts.
 *   { status:200, etag, changed:false, entries:[] }        — unchanged since `sinceEtag` (NO decrypt, mk unused)
 *   { status:200, etag, changed:true, version, entries }   — the new plaintext entries after `sinceCount`
 *   { status:404 }                                         — no ledger yet
 *   { status:400 }                                         — bad request
 *  Deps injectable for tests (getRaw/getFull/setKey). `mk` is used ONLY on a real change, then dropped. */
// Boxes present in the raw ledger. The per-entry (v3) reader DROPS a box the key cannot open rather than failing, so a
// wrong key decodes a full ledger to [] — and [] read as "an empty room": a blank screen, no banner, on both tiers
// (measured live 2026-10-03 with a random key: 200, version 0, entries []). Boxes present and nothing opened is the same
// verdict as a null decrypt: 422 'undecodable', which the page already knows how to say.
const sealedHasBoxes = (raw) => { try { const p = typeof raw === 'string' ? JSON.parse(raw) : raw; return isV3(p) && p.boxes.length > 0 } catch { return false } }

export async function pollSpaceView({ room, mk, sinceEtag, sinceCount = 0 } = {}, deps = {}) {
  const { getFull = getLedger, setKey = setRoomKey, getPartial = getPartialRaw, getDeviceCall = getDeviceCallRaw } = deps
  if (!room) return { status: 400 }
  // The in-progress reply rides this path too. `poll` is the DEFAULT loop (pollsealed is still behind ?localopen), so
  // shipping progressive replies only on the content-blind path would have shipped them to nobody. Sealed either way:
  // this handler decrypts the ledger, but the partial is passed through untouched and opened by the client.
  const partial = await getPartial(room).catch(() => null)
  const deviceCall = await getDeviceCall(room).catch(() => null) // a parked client-tool call (e.g. calendar) for the device to run — passed through sealed, opened by the client
  const withPartial = (o) => { const p = withTurnProgress(o, partial); return deviceCall ? { ...p, deviceCall: deviceCall.box, deviceCallSeq: deviceCall.seq } : p }
  const read = await readLedgerForPoll(room, sinceEtag, deps) // ciphertext, no key — only to tag it; NEVER sent to the client
  if (read.unchanged) return withPartial({ status: 200, etag: read.unchanged, changed: false, entries: [] }) // no read, no decrypt, mk unused
  const sealed = read.sealed
  // A room with no ledger yet is EMPTY, not "not found": a Space is created before its first message (e.g. the embed /
  // Lumen mints a fresh room and immediately polls it), so `null` here means zero entries, not a missing room. Returning
  // 404 stranded a just-created room's poll loop; an empty room is a plain 200 with no entries.
  if (sealed == null) return withPartial({ status: 200, changed: false, entries: [], version: 0 })
  const etag = read.etag
  if (sinceEtag && sinceEtag === etag) return withPartial({ status: 200, etag, changed: false, entries: [] }) // no decrypt, mk unused

  if (!mk) return { status: 401 } // a changed ledger needs mk to render — the client must supply it for the active window
  setKey(mk)
  try {
    const ledger = await getFull(room) // DECRYPT IN THE LAMBDA
    // getRaw above already returned the sealed blob (we're past the 404), so a null decrypt here is NOT an empty room —
    // it's an mk that can't OPEN the blob (a wrong/incomplete invite key). Signal it distinctly (422) so the client can
    // say "couldn't unlock this Space's history" instead of rendering a blank room indistinguishable from empty. (A real
    // ledger is never persisted empty, so `null` unambiguously means undecodable, not zero entries.)
    if (ledger == null) return { status: 422, etag, changed: true, reason: 'undecodable' }
    const all = Array.isArray(ledger) ? ledger : []
    if (all.length === 0 && sealedHasBoxes(sealed)) return { status: 422, etag, changed: true, reason: 'undecodable' } // v3: every box refused the key (see sealedHasBoxes)
    const from = Number.isInteger(sinceCount) && sinceCount > 0 ? Math.min(sinceCount, all.length) : 0
    const pg = pageEntries(all.slice(from), from, etag) // paged like the sealed view (see pageV3): version = the page's end, a paging etag while more remains
    return withPartial({ status: 200, etag: pg.etag, changed: true, version: pg.more ? pg.version : all.length, entries: pg.entries, ...(pg.more ? { more: true } : {}) })
  } finally {
    setKey(null) // DROP mk — never held between polls
  }
}

/** Poll a Space CONTENT-BLIND — hand back the SEALED blob and let the client open it. The counterpart to
 *  pollSpaceView: same room, same etag, but `mk` NEVER appears on this path (not in the request, not in this process).
 *  That matters because poll is the hot loop — it fires every ~600ms while a Space is on screen, so it was carrying the
 *  room key hundreds of times per session where a turn carries it a handful. Moving the open to the client removes the
 *  key from the highest-frequency op entirely; what remains is `turn`, which genuinely needs plaintext for the agent.
 *   { status:200, etag, changed:false }             — unchanged since `sinceEtag` (no blob ⇒ an idle poll costs nothing)
 *   { status:200, etag, changed:true, sealed }      — the exact ciphertext at rest; the client opens it with mk
 *   { status:404 }                                  — no ledger yet
 *   { status:400 }                                  — bad request
 *  There is no 422 here: an mk that can't open the blob is discovered BY THE CLIENT, which is the more honest place for
 *  it — the reader proves the key fits rather than taking the server's word. Serving ciphertext to an un-keyed caller
 *  reveals nothing (the same reasoning as op:'sealed'), but callers must still apply the room's READ GATE — see
 *  EMAIL_GATED_OPS in spaceService: for an email-gated Space, holding mk must not by itself buy the bytes. */
export async function pollSealedView({ room, sinceEtag, sinceCount } = {}, deps = {}) {
  const { getPartial = getPartialRaw, getDeviceCall = getDeviceCallRaw, getNotif = getNotifRaw } = deps
  if (!room) return { status: 400 }
  // The IN-PROGRESS reply rides EVERY response, including the unchanged one. While a reply is still being written the
  // ledger does not move, so gating the partial behind `changed` would mean it never arrived — the whole point is to
  // deliver text before the entry exists. Sealed: passed through verbatim, opened by the client.
  const partial = await getPartial(room).catch(() => null)
  const deviceCall = await getDeviceCall(room).catch(() => null) // a parked client-tool call (e.g. calendar) for the device to run — passed through sealed, opened by the client
  // Phase-4: the newest entry's NK-sealed preview, passed through verbatim (content-blind) — the Service Worker opens it
  // with the mirrored NK to compose a push WITHOUT mk. Rides every response (null until the writer stores one).
  const notif = await getNotif(room).catch(() => null)
  const withPartial = (o) => { let p = withTurnProgress(o, partial); if (deviceCall) p = { ...p, deviceCall: deviceCall.box, deviceCallSeq: deviceCall.seq }; if (notif) p = { ...p, notif: JSON.stringify(notif) }; return p }
  const read = await readLedgerForPoll(room, sinceEtag, deps)
  if (read.unchanged) return withPartial({ status: 200, etag: read.unchanged, changed: false }) // the tag alone answered: nothing read
  const sealed = read.sealed
  if (sealed == null) return withPartial({ status: 200, changed: false }) // a fresh, message-less room is EMPTY, not 404 (same reasoning as pollSpaceView)
  const etag = read.etag
  if (sinceEtag && sinceEtag === etag) return withPartial({ status: 200, etag, changed: false })
  // v3 per-entry ledger → hand back only boxes[sinceCount:] + the total count (a pure index slice, still content-blind:
  // no key touched). v1/v2 are one opaque blob (sliceRawV3 → null) → return the whole thing, exactly as before. So this
  // is a no-op on today's data and only kicks in once the writer emits v3 (reader-first — clients must accept a slice first).
  const slice = sliceRawV3(sealed, sinceCount)
  // `done` rides along when the ledger records one: a peer drops its thinking indicator the moment this
  // ADVANCES, which is the only event a SILENT turn produces. Absent on v1/v2 → the client falls back.
  if (slice) {
    const pg = pageV3(slice, etag)
    // `done` only with the LAST page: on a partial page it could point past `count`, and the client reads it as
    // "entries through a completed turn" relative to what it holds.
    return withPartial({ status: 200, etag: pg.etag, changed: true, sealed: JSON.stringify(pg.slice), from: pg.slice.from, count: pg.slice.count, ...(pg.more ? { more: true } : {}), ...(pg.more || slice.done === undefined ? {} : { done: slice.done }) })
  }
  if (sealed.length > PAGE_MAX_BYTES) return withPartial({ status: 413, etag, changed: true, reason: 'ledger_too_large', bytes: sealed.length }) // a legacy single blob cannot be paged — say so, rather than let the runtime fail the response
  return withPartial({ status: 200, etag, changed: true, sealed })
}

// ★ A POLL IS PAGED, so a room's history can never outgrow what a Lambda may answer. The runtime caps a response at
//   6 MB; a Space with a few PDFs and tickets in its ledger (files ride the entries as base64, up to ~3.7 MB each) passes
//   that, and the poll that builds it FAILS AFTER doing all the work — the handler returns, the runtime refuses the
//   body, the client gets a bare error and asks again on its next tick. Measured 2026-09-18: ~250 such failures per
//   half hour, three live ledgers of 7.8–11.4 MB, and a device loading one from zero looping forever on it. A page keeps
//   the serialized slice under PAGE_MAX_BYTES (headroom for the partial, notif and JSON around it); `count` becomes the
//   page's END — the client already takes that as its next sinceCount — and the etag is a PAGING etag that can never
//   equal the stored one, so the client's next poll (sinceEtag ≠ etag) is `changed` and fetches the next page. The last
//   page carries the real etag and settles. No client change: paging is the existing delta contract, applied to a load.
export const PAGE_MAX_BYTES = 4_500_000
export function pageV3(slice, etag) {
  const boxes = slice.boxes || []
  let bytes = 0, k = 0
  for (; k < boxes.length; k++) { const b = String(boxes[k]).length + 3; if (k > 0 && bytes + b > PAGE_MAX_BYTES) break; bytes += b }
  if (k >= boxes.length) return { slice, etag, more: false }
  const end = slice.from + k
  return { slice: { ...slice, boxes: boxes.slice(0, k), count: end }, etag: etag + '#' + end, more: true }
}
/** The plaintext view's page: the same rule over decrypted entries (sized as JSON). */
export function pageEntries(entries, from, etag) {
  let bytes = 0, k = 0
  for (; k < entries.length; k++) { const b = JSON.stringify(entries[k]).length + 1; if (k > 0 && bytes + b > PAGE_MAX_BYTES) break; bytes += b }
  if (k >= entries.length) return { entries, version: from + entries.length, etag, more: false }
  return { entries: entries.slice(0, k), version: from + k, etag: etag + '#' + (from + k), more: true }
}
