// PROTOTYPE — v3 per-entry-sealed chat ledger.
//
// Today the ledger is ONE opaque blob: putLedger seals JSON.stringify({v,entries}) as a single envelope, so every
// message re-encrypts the whole conversation (O(N) write) and every poll-with-change ships + decrypts the whole thing
// (O(N) read) — quadratic over a Space's life, and the SERVER can never slice it (the entries live inside ciphertext).
//
// v3 moves the sealing granularity from WHOLE-LEDGER to PER-ENTRY. The stored ledger becomes a PLAINTEXT wrapper
// `{ v:3, boxes:[<sealed-entry>, …] }`: the array structure is visible to the server (so it can slice by index,
// content-blind), while each box stays individually sealed to the room key. Result:
//   • O(1) write crypto  — append seals ONLY the new entry; existing boxes are byte-for-byte untouched.
//   • O(new) read        — the server returns boxes[sinceCount:] without ever holding a key.
// Metadata leaked (box count + sizes) is exactly what the single blob's own size already leaked.
//
// READER-FIRST: `readLedgerEntries` also opens v1 (bare-array, whole-sealed) and v2 ({v,entries}, whole-sealed), so
// this format can ship to every reader BEFORE any writer emits it (the sessionStore.mjs versioning discipline). Only
// when readers are field-saturated do you flip the writer to `appendV3` — old blobs lazy-migrate on their next write.

import { seal, open, isEnvelope } from './envelope.mjs'

export const LEDGER_V3 = 3
export const isV3 = (x) => !!x && typeof x === 'object' && x.v === LEDGER_V3 && Array.isArray(x.boxes)

// M4 (docs security review): bind each box to its {room, absolute-index} via the AES-GCM AAD, so a content-blind store
// can't reorder / duplicate / replay boxes within a room undetectably — a moved box fails auth on open. The stored ledger
// is APPEND-ONLY, so a box's absolute index is stable for its whole life (compaction rewrites only the PROMPT context, not
// the stored boxes). `ledgerAad` MUST stay byte-identical to the client twin (spaces/public/spaceClient.js) — unit-separated
// so it can never collide with a room id.
const enc = new TextEncoder()
export const ledgerAad = (room, index) => enc.encode('v3\x1f' + String(room) + '\x1f' + String(index))
// WRITER flag (default OFF): emit aad-bound boxes only once every reader is field-saturated. Readers SELF-ADAPT per box
// (the aad:1 marker on the envelope), so no reader flag is needed — this mirrors the reader-first LEDGER_V3 rollout.
const aadWrite = () => String((typeof process !== 'undefined' && process.env && process.env.LEDGER_AAD) || '') === '1'

/** Seal ONE entry → an opaque box string (same envelope format as encodeMemory, just per-entry). null with no key.
 *  Pass `aad` (from ledgerAad) to bind the box to its {room,index}; omit for a legacy (unbound) box. */
export async function sealEntry(entry, { mk, aad = null } = {}) {
  if (!mk) return null // no room key → never write (fail-safe, mirrors putLedger)
  return JSON.stringify(await seal(JSON.stringify(entry), { mk, aad }))
}

/** Open ONE box → the entry, or null (no key / wrong key / tamper / malformed / moved). Pass the SAME `aad` the box was
 *  sealed with (a bound box refuses to open without it; a legacy box ignores it). */
export async function openEntry(box, { mk, aad = null } = {}) {
  try {
    const env = JSON.parse(box)
    if (!isEnvelope(env)) return null
    const pt = await open(env, { mk, aad })
    return pt == null ? null : JSON.parse(pt)
  } catch { return null }
}

/** WRITER: append `entry` to the prior v3 ledger string → the new v3 string (store via putRaw). Only the new entry is
 *  sealed; the existing boxes are carried through unchanged (no re-encrypt of history). null with no key ⇒ don't write.
 *  When LEDGER_AAD=1 and `room` is supplied, the new box is AAD-bound to {room, its append index}. */
export async function appendV3(prevRaw, entry, { mk, room = null } = {}) {
  let boxes = []
  let done // carried through — an append must not erase a recorded resolution
  try {
    const p = typeof prevRaw === 'string' ? JSON.parse(prevRaw) : prevRaw
    if (isV3(p)) { boxes = p.boxes; if (Number.isInteger(p.done)) done = p.done }
  } catch { /* fresh/legacy → start clean */ }
  const index = boxes.length // absolute position of the NEW box — stable for its life (append-only ledger)
  const aad = aadWrite() && room != null ? ledgerAad(room, index) : null
  const box = await sealEntry(entry, { mk, aad })
  if (box == null) return null
  return JSON.stringify({ v: LEDGER_V3, boxes: [...boxes, box], ...(done === undefined ? {} : { done }) })
}

/** SERVER SLICE — CONTENT-BLIND (no mk). Given the RAW stored ledger string, return the v3 wrapper holding only the
 *  boxes AFTER `sinceCount`, plus the total `count`. Returns null when the ledger is NOT v3 (v1/v2 opaque blob ⇒ the
 *  caller must hand back the whole thing; it cannot be sliced without the key). Pure index math — never decrypts. */
export function sliceRawV3(raw, sinceCount = 0) {
  let p
  try { p = typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return null }
  if (!isV3(p)) return null
    const total = p.boxes.length
  const from = Number.isInteger(sinceCount) && sinceCount > 0 ? Math.min(sinceCount, total) : 0
  // `done` — how many entries have been through a COMPLETED turn. Plaintext on the wrapper, so carrying it
  // costs no key and no decrypt. It is what lets a peer know a turn ended in SILENCE: the agent writes no
  // entry then, so the boxes are unchanged and `done` advancing is the only observable event.
  const done = Number.isInteger(p.done) ? p.done : undefined
  return { v: LEDGER_V3, boxes: p.boxes.slice(from), from, count: total, ...(done === undefined ? {} : { done }) }
}

/** READER-FIRST decode → the entries array, whatever the stored shape is:
 *   • v1  — a bare array sealed as one blob (envelope) → decrypt whole.
 *   • v2  — { v, entries } sealed as one blob (envelope) → decrypt whole.
 *   • v3  — { v:3, boxes:[…] } plaintext wrapper of per-entry boxes → open each box.
 *  Accepts either the full stored ledger OR a v3 SLICE (from sliceRawV3) — a slice is just a v3 wrapper with fewer boxes. */
export async function readLedgerEntries(raw, { mk, room = null } = {}) {
  let p
  try { p = typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return [] }
  if (isEnvelope(p)) { // v1 / v2 — one sealed blob
    const pt = await open(p, { mk })
    if (pt == null) return []
    let o
    try { o = JSON.parse(pt) } catch { return [] }
    return Array.isArray(o) ? o : (o && Array.isArray(o.entries) ? o.entries : [])
  }
  if (isV3(p)) { // v3 — per-entry boxes
    const base = Number.isInteger(p.from) ? p.from : 0 // a SLICE carries its absolute offset (sliceRawV3.from); a full ledger has none → 0
    const out = []
    for (let i = 0; i < p.boxes.length; i++) {
      const aad = room != null ? ledgerAad(room, base + i) : null // absolute index = slice offset + position; a legacy box ignores it, a bound box verifies it
      const e = await openEntry(p.boxes[i], { mk, aad })
      if (e != null) out.push(e)
    }
    return out
  }
  return []
}
