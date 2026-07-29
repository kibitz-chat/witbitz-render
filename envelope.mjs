// Multi-recipient envelope for platform-blind agent memory (docs/encrypted-memory.md). A fresh per-write content
// key (CEK) encrypts the blob; the CEK is wrapped once PER RECIPIENT, so the same ciphertext can be opened by any
// recipient that holds its key:
//   - room: symmetric — AES-256-GCM under HKDF(mk,"memwrap"); `mk` is the CREATOR's high-entropy 32-byte key
//     (lives in the room-link fragment, delivered to the agent over E2EE — the server never sees it).
//   - beta: symmetric — the SAME wrap, but under the operator's per-room BETA key (betaKey.mjs). Present when beta
//     mode is on, so a gift can be sealed to the creator (room) AND still opened by the operator (beta) for support
//     — dual-recipient. Dropping beta = a true platform-blind room (creator-only).
//   - admin (DEBUG only): asymmetric — RSA-OAEP-SHA256 under the operator's OFFLINE public key (private half off-AWS).
//
// On-disk shape (replaces today's plaintext JSON.stringify(memory)):
//   { v:1, iv, ct, recipients:{ room?:{iv,w}, beta?:{iv,w}, admin?:{kid,w} } }   (all bytes base64url)
//
// Everything on disk is public ciphertext; `mk` (and the admin PRIVATE key) are the only secrets. open() fails
// CLOSED (returns null ⇒ caller treats it as "no prior memory") on wrong key / tamper / malformed — mirroring
// seal.mjs. mk is already high-entropy random, so the room wrap derives via HKDF (cheap), NOT seal.mjs's 210k-iter
// PBKDF2 (that stays for any passphrase path).
import { webcrypto as crypto } from 'node:crypto'

const enc = new TextEncoder()
const dec = new TextDecoder()
const VERSION = 1
const b64 = (b) => Buffer.from(b).toString('base64url')
const ub64 = (s) => new Uint8Array(Buffer.from(String(s || ''), 'base64url'))

// mk (base64url, 32 random bytes) → an AES-256-GCM wrap key via HKDF. Stable info string so reads match writes.
async function roomWrapKey(mk) {
  const ikm = await crypto.subtle.importKey('raw', ub64(mk), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('memwrap') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
// SPKI PEM (standard base64, with or without the -----BEGIN----- header) → an RSA-OAEP-SHA256 public key.
async function importAdminPub(pem) {
  const der = new Uint8Array(Buffer.from(String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'))
  return crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
}

/** A fresh random room key (base64url) — what the creator mints + puts in the room-link fragment. */
export function newRoomKey() {
  return b64(crypto.getRandomValues(new Uint8Array(32)))
}

/** Commitment to a room key: base64url(SHA-256(mk-string)). The creator puts this in the summon (the server sees
 *  only this hash, never mk); the agent accepts an incoming mk ONLY if commit(mk) matches — anti-poisoning without
 *  identity, platform-blind preserved. Both sides MUST hash the same mk STRING representation. */
export async function commit(mk) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(String(mk || '')))
  return b64(new Uint8Array(h))
}

// ── 2-of-2 SHARED-PRESENCE secret sharing (M1b, docs/shared-presence-m1b.md). Split the room key into TWO shares (one
// per partner): NEITHER opens the room alone; only BOTH together reconstruct mk. XOR = perfect 2-of-2 secrecy (a single
// share is information-theoretically independent of mk). "The room opens only when both are present" — cryptographic,
// not policy. Server holds only commit(mk). Wire-identical to e2ee.js. (2-of-2 only; k-of-n → Shamir later.)
/** Split mk into { shareA, shareB } (each base64url). shareA random, shareB = mk XOR shareA. */
export function splitKey(mk) {
  const k = ub64(mk)
  if (!k.length) throw new Error('splitKey needs a key')
  const a = crypto.getRandomValues(new Uint8Array(k.length))
  const b = new Uint8Array(k.length)
  for (let i = 0; i < k.length; i++) b[i] = k[i] ^ a[i]
  return { shareA: b64(a), shareB: b64(b) }
}
/** Reconstruct mk from BOTH shares (ORDER-INDEPENDENT). Returns base64url mk, or null if the shares don't pair up.
 *  Verify with commit(mk) === the stored commitment before trusting it. */
export function combineShares(shareA, shareB) {
  const a = ub64(shareA || '')
  const b = ub64(shareB || '')
  if (!a.length || a.length !== b.length) return null
  const mk = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) mk[i] = a[i] ^ b[i]
  return b64(mk)
}
/** The both-present OPEN gate: combine two shares AND verify against the Space's stored commitment. Returns mk only if
 *  both shares reconstruct the committed key — else null (a lone/wrong/tampered share ⇒ the room stays sealed). */
export async function assembleRoomKey(shareA, shareB, expectedCommit) {
  const mk = combineShares(shareA, shareB)
  if (mk == null) return null
  if (expectedCommit && (await commit(mk)) !== expectedCommit) return null
  return mk
}

// Wrap the CEK under a symmetric room/beta key (HKDF(key,"memwrap")) → { iv, w }.
async function wrapSym(key, cek) {
  const wk = await roomWrapKey(key)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const w = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wk, cek))
  return { iv: b64(iv), w: b64(w) }
}

/** Seal a string for one or more recipients. opts: { mk?, betaMk?, adminPubKey?, adminKid? } — at least one is
 *  required. room (mk) is the CREATOR/platform-blind reader; beta (betaMk) is the operator's per-room key so the
 *  same record stays operator-readable while beta mode is on (dual-recipient); admin (RSA pubkey) is the offline
 *  debug reader. A DEBUG session with no room key still seals (admin/beta-only) without breaking no-key-no-plaintext.
 *  Returns the envelope object (JSON-serializable). */
export async function seal(plaintext, { mk, betaMk, adminPubKey, adminKid } = {}) {
  if (!mk && !betaMk && !adminPubKey) throw new Error('seal needs at least one recipient (mk, betaMk, or adminPubKey)')
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cekKey, enc.encode(String(plaintext))))
  const recipients = {}
  if (mk) recipients.room = await wrapSym(mk, cek) // creator / platform-blind reader
  if (betaMk) recipients.beta = await wrapSym(betaMk, cek) // operator's per-room beta key (dual-recipient)
  // admin recipient (asymmetric, RSA-OAEP) — debug/operator, decrypts OFFLINE with the private half
  if (adminPubKey) {
    const pub = await importAdminPub(adminPubKey)
    const aw = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, cek))
    recipients.admin = { kid: adminKid || '', w: b64(aw) }
  }
  return { v: VERSION, iv: b64(iv), ct: b64(ct), recipients }
}

/** Open an envelope with a symmetric key (mk) → the plaintext string, or null on wrong key / tamper / malformed.
 *  Tries the SAME key against every symmetric recipient (room, then beta), so ONE call opens the record whether the
 *  caller holds the creator's mk (room) or the operator's beta key (beta). Wrong key → GCM auth fails → next/null. */
export async function open(envelope, { mk } = {}) {
  if (!isEnvelope(envelope) || !mk) return null
  const wk = await roomWrapKey(mk)
  for (const slot of ['room', 'beta']) {
    const r = envelope.recipients[slot]
    if (!r) continue
    try {
      const cek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(r.iv) }, wk, ub64(r.w)))
      const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt'])
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(envelope.iv) }, cekKey, ub64(envelope.ct)))
      return dec.decode(pt)
    } catch {
      // this recipient didn't match the key (or tamper) — try the next symmetric recipient, else fail closed
    }
  }
  return null
}

/** True if a stored object is a v1 envelope (vs legacy pre-encryption plaintext). At least one recipient. */
export function isEnvelope(o) {
  return !!(o && typeof o === 'object' && o.v === VERSION && typeof o.iv === 'string' && typeof o.ct === 'string' && o.recipients && (o.recipients.room || o.recipients.beta || o.recipients.admin))
}

// ── Binary sealing (keepsake clips/images) ──────────────────────────────────────────────────────────────────────
// Same CEK-wrap model as seal(), but the ciphertext is returned as RAW BYTES (the `body`, e.g. the S3 object) rather
// than base64'd into JSON — so a multi-MB video isn't bloated ~33% or forced through a JSON parse. The small `header`
// (the per-recipient wrapped CEK + the content IV) is JSON-serializable → store it as artifact metadata. Open with
// openBytes(body, header, { mk }). Wire-compatible with witz/public/e2ee.js sealBytes/openBytes (browser ⇄ agent).
export async function sealBytes(bytes, { mk, betaMk, adminPubKey, adminKid } = {}) {
  if (!mk && !betaMk && !adminPubKey) throw new Error('sealBytes needs at least one recipient (mk, betaMk, or adminPubKey)')
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cekKey, data))
  const recipients = {}
  if (mk) recipients.room = await wrapSym(mk, cek)
  if (betaMk) recipients.beta = await wrapSym(betaMk, cek)
  if (adminPubKey) {
    const pub = await importAdminPub(adminPubKey)
    const aw = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, cek))
    recipients.admin = { kid: adminKid || '', w: b64(aw) }
  }
  return { header: { v: VERSION, alg: 'bin', iv: b64(iv), recipients }, body }
}

/** Open a sealBytes body + header with a symmetric key → plaintext BYTES (Uint8Array), or null on wrong key / tamper /
 *  malformed (fail-closed). Tries the key against room then beta, mirroring open(). */
export async function openBytes(body, header, { mk } = {}) {
  if (!isBinHeader(header) || !mk || !body) return null
  const data = body instanceof Uint8Array ? body : new Uint8Array(body)
  const wk = await roomWrapKey(mk)
  for (const slot of ['room', 'beta']) {
    const r = header.recipients[slot]
    if (!r) continue
    try {
      const cek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(r.iv) }, wk, ub64(r.w)))
      const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt'])
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(header.iv) }, cekKey, data))
    } catch {
      // wrong key / tamper for this slot → try the next symmetric recipient, else fail closed
    }
  }
  return null
}

/** True if `h` is a v1 binary-envelope header (from sealBytes) — distinct from a string envelope (which carries `ct`). */
export function isBinHeader(h) {
  return !!(h && typeof h === 'object' && h.v === VERSION && h.alg === 'bin' && typeof h.iv === 'string' && h.recipients && (h.recipients.room || h.recipients.beta || h.recipients.admin))
}

// ── Sealed box (PUBLIC-KEY) — for CONTRIBUTOR wishes ──────────────────────────────────────────────────────────────
// A friend seals a wish to the ORGANIZER's PUBLIC key (encrypt-only); ONLY the organizer's PRIVATE key (recoverable
// from mk) opens it. Anonymous sealed box: fresh EPHEMERAL ECDH-P256 per message → HKDF → AES-256-GCM, sender key
// discarded. The agent opens contributed wishes here with the mk-derived private key (the transient render). No secret
// is shared with contributors. Wire-compatible with witz/public/e2ee.js (same ECDH-P256 + HKDF("sealedbox") + AES-GCM).
const EC = { name: 'ECDH', namedCurve: 'P-256' }
async function boxKey(priv, pubJwk) {
  const privKey = priv && priv.kty ? await crypto.subtle.importKey('jwk', priv, EC, false, ['deriveBits']) : priv
  const pub = await crypto.subtle.importKey('jwk', pubJwk, EC, false, [])
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, privKey, 256)
  const ikm = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('sealedbox') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
/** Generate a recipient (organizer) keypair → { publicJwk, privateJwk }. Publish publicJwk; wrap privateJwk to mk. */
export async function genRecipientKey() {
  const kp = await crypto.subtle.generateKey(EC, true, ['deriveBits'])
  return { publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey), privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey) }
}
/** Seal a string to a recipient PUBLIC key (jwk) → an anonymous sealed box. Encrypt-only. */
export async function sealTo(plaintext, recipientPublicJwk) {
  if (!recipientPublicJwk) throw new Error('sealTo needs the recipient public key')
  const eph = await crypto.subtle.generateKey(EC, true, ['deriveBits'])
  const key = await boxKey(eph.privateKey, recipientPublicJwk)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(String(plaintext))))
  const epk = await crypto.subtle.exportKey('jwk', eph.publicKey)
  return { v: VERSION, alg: 'box', epk: { x: epk.x, y: epk.y }, iv: b64(iv), ct: b64(ct) }
}
/** Open a sealed box with the recipient PRIVATE key (jwk) → plaintext string, or null (fail-closed). */
export async function openBox(box, recipientPrivateJwk) {
  if (!isBox(box) || !recipientPrivateJwk) return null
  try {
    const key = await boxKey(recipientPrivateJwk, { kty: 'EC', crv: 'P-256', x: box.epk.x, y: box.epk.y })
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(box.iv) }, key, ub64(box.ct)))
    return dec.decode(pt)
  } catch {
    return null
  }
}
/** True if a stored value is a v1 sealed box (public-key). */
export function isBox(o) {
  return !!(o && typeof o === 'object' && o.v === VERSION && o.alg === 'box' && o.epk && typeof o.epk.x === 'string' && typeof o.iv === 'string' && typeof o.ct === 'string')
}

// ── Nested collection blob — content-blind append + owner peel (docs/e2ee-collection-blob.md) ─────────────────────
// Each append wraps { the contributor's box, the previous blob } in a fresh sealed layer to the owner's PUBLIC key, so
// the Lambda appends WITHOUT decrypting (content-blind); only the owner's PRIVATE key (from mk) peels. The agent uses
// peelAll to read the wishes and (at call-end) COMPACTS by peeling + re-sealing flat. Wire-compatible with e2ee.js.
/** True if a value is a collection blob (an append-only list of sealed boxes). Accepts the raw DynamoDB shape too. */
export function isBoxList(o) { return !!(o && typeof o === 'object' && Array.isArray(o.boxes)) }
/** A stable, opaque id for a box — a prefix of its ciphertext (unique per box). Sync, no key: the console + the agent
 *  derive the SAME id to key moderation (leave-out) decisions without decrypting. Must match e2ee.js boxId byte-for-byte. */
export function boxId(box) { return String((box && box.ct) || '').slice(0, 40) }
/** Append one contributor box to the blob (immutable — returns a new blob). No key needed; the box is already sealed. */
export function appendBox(blob, box) {
  const boxes = isBoxList(blob) ? blob.boxes : []
  return { v: VERSION, alg: 'boxlist', boxes: [...boxes, box] }
}
/** Owner/agent read: open every box with the PRIVATE key → items. Handles the boxlist blob AND a bounded onion (below). */
export async function peelAll(blob, ownerPrivateJwk) {
  if (isBoxList(blob)) { // the collection-blob form (also the raw DynamoDB { boxes:[...] } item)
    const out = []
    for (const b of blob.boxes) { const item = await openBox(b, ownerPrivateJwk); if (item != null) out.push(item) }
    return out
  }
  const out = [] // bounded onion form (nestAppend) — newest-first
  let cur = blob
  while (cur && isBox(cur)) {
    const layer = await openBox(cur, ownerPrivateJwk)
    if (layer == null) break
    let parsed
    try { parsed = JSON.parse(layer) } catch (e) { break }
    if (parsed && parsed.inner) { const item = await openBox(parsed.inner, ownerPrivateJwk); if (item != null) out.push(item) }
    cur = parsed && parsed.prev ? parsed.prev : null
  }
  return out
}
/** BOUNDED-USE onion append: wrap { box, prev } in a fresh layer to the PUBLIC key. WARNING: size is EXPONENTIAL in the
 *  number of appends — use ONLY for a small, bounded count (e.g. a compaction). The async collection uses appendBox. */
export async function nestAppend(oldBlob, contributorBox, ownerPublicJwk) {
  return sealTo(JSON.stringify({ inner: contributorBox, prev: oldBlob || null }), ownerPublicJwk)
}

// ── The collection keypair — minted at create, PUBLIC published, PRIVATE wrapped to mk (docs/e2ee-collection-blob.md) ─
// The owner's read key is `mk` (never shared). At create the organizer mints a recipient keypair: the PUBLIC jwk is
// published on the gift record; the PRIVATE jwk is symmetric-sealed to `mk`. Anyone holding `mk` (organizer console, or
// the agent at call time) unwraps it to peel the blob. The wrapped key is wire-compatible with e2ee.js (the `room` slot).
/** Mint a collection keypair → { publicJwk (publish), wrapped (store; the private jwk sealed to mk) }. */
export async function sealRecipientKey(mk) {
  if (!mk) throw new Error('sealRecipientKey needs mk')
  const { publicJwk, privateJwk } = await genRecipientKey()
  const wrapped = await seal(JSON.stringify(privateJwk), { mk })
  return { publicJwk, wrapped }
}
/** Unwrap the private jwk from its mk-sealed envelope → privateJwk, or null (fail-closed on wrong mk / tamper). */
export async function openRecipientKey(mk, wrapped) {
  if (!mk || !isEnvelope(wrapped)) return null
  const s = await open(wrapped, { mk })
  if (s == null) return null
  try { return JSON.parse(s) } catch (e) { return null }
}
