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
import { getLedgerRaw, getLedger } from './sessionStore.mjs'

const enc = new TextEncoder()
const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** etag = a hash of the SEALED blob (ciphertext) — the cheap change-tag. Computed WITHOUT decrypting; reveals only
 *  "changed", not the turn count. Deterministic per stored blob → an unchanged ledger yields a stable etag. */
export async function etagOf(sealed) {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(sealed)))).slice(0, 22)
}

/** Poll a Space, PROCESSED IN THE LAMBDA. The blob is never returned — only plaintext entries the Lambda decrypts.
 *   { status:200, etag, changed:false, entries:[] }        — unchanged since `sinceEtag` (NO decrypt, mk unused)
 *   { status:200, etag, changed:true, version, entries }   — the new plaintext entries after `sinceCount`
 *   { status:404 }                                         — no ledger yet
 *   { status:400 }                                         — bad request
 *  Deps injectable for tests (getRaw/getFull/setKey). `mk` is used ONLY on a real change, then dropped. */
export async function pollSpaceView({ room, mk, sinceEtag, sinceCount = 0 } = {}, deps = {}) {
  const { getRaw = getLedgerRaw, getFull = getLedger, setKey = setRoomKey } = deps
  if (!room) return { status: 400 }
  const sealed = await getRaw(room) // ciphertext, no key — only to compute the etag; NEVER sent to the client
  if (sealed == null) return { status: 404 }
  const etag = await etagOf(sealed)
  if (sinceEtag && sinceEtag === etag) return { status: 200, etag, changed: false, entries: [] } // no decrypt, mk unused

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
    const from = Number.isInteger(sinceCount) && sinceCount > 0 ? Math.min(sinceCount, all.length) : 0
    return { status: 200, etag, changed: true, version: all.length, entries: all.slice(from) }
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
export async function pollSealedView({ room, sinceEtag } = {}, deps = {}) {
  const { getRaw = getLedgerRaw } = deps
  if (!room) return { status: 400 }
  const sealed = await getRaw(room)
  if (sealed == null) return { status: 404 }
  const etag = await etagOf(sealed)
  if (sinceEtag && sinceEtag === etag) return { status: 200, etag, changed: false }
  return { status: 200, etag, changed: true, sealed }
}
