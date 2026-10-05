// Session-memory store (docs/agent-persistence.md, brick 4; sealing per docs/encrypted-memory.md). Stores a living
// call's memory to S3 keyed by agent+room and fetches it back on resume. PLATFORM-BLIND: the blob is SEALED with
// the room key (mk) the agent received over E2EE — the operator sees ciphertext only. FAIL-SAFE: no mk ⇒ nothing is
// written or read (in-session memory only) — strictly better than the old plaintext-always default, and the safe
// behavior for clients that don't deliver a key. FAIL-SOFT: any S3 error → start/leave clean; never crash the call.
import { logRoom } from './logRoom.mjs' // a log names a room by a hash, never the id (the log privacy audit)
import { s3ClientOptions } from './adapters.mjs'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { createHash, randomUUID } from 'node:crypto' // the local store's ETag emulation (appendLedger's compare-and-set)
import { seal, open, isEnvelope } from './envelope.mjs'
import { getRoomKey, setRoomKey, hasAnyKey } from './roomKey.mjs'
import { isV3, sealEntry, openEntry, readLedgerEntries, ledgerAad } from './spaceLedgerV3.mjs'
import { parseV4Header, readAllSegments, tailTag, tagFromTail, writeGeneration, appendOnce, rewriteSegments, touchHeader } from './ledgerSegments.mjs' // v4: the ledger in segments (docs/ledger-segments.md)
import { notifForEntry } from './notif.mjs' // Phase-4: seal the newest entry's preview under NK for content-free-but-rich push

const BUCKET = process.env.MEMORY_BUCKET || ''
// TEMPORARY ROOMS (infra/temp-spaces.tf): a room whose id is namespaced `tmp-…` is "wiped when not in use". Its
// sealed objects live in a SEPARATE un-versioned, no-backup bucket (TEMP_BUCKET) so a delete/expiry there actually
// destroys the bytes. Routing is by KEY at the single S3 choke point below — the room is always the trailing key
// segment, so every doc type (ledger/title/authority/push/widget/partial/raw/notif/devicecall/…) is covered WITHOUT
// touching any key function. Flag-gated: with TEMP_BUCKET unset — or no `tmp-` rooms in existence — every read/write
// resolves to BUCKET exactly as today, so this is byte-identical to current behaviour until deliberately wired on.
const TEMP_BUCKET = process.env.TEMP_BUCKET || ''
export const isTempRoom = (room) => String(room || '').startsWith('tmp-')
const isTempKey = (key) => (String(key || '').split('/').pop() || '').startsWith('tmp-') // room = trailing segment
const bucketFor = (key) => (TEMP_BUCKET && isTempKey(key) ? TEMP_BUCKET : BUCKET)
// DEV/E2E: a local directory to store the SEALED memory blob instead of S3 — fully-local persistence (no AWS), so a
// resume round-trip can be exercised on one box. Same seal/open + key gating as S3; only the object I/O differs.
const LOCAL_DIR = process.env.MEMORY_LOCAL_DIR || ''
// A key/value store reached over HTTP instead of S3 or the filesystem. This exists for the ATTESTED tier: an enclave
// has no AWS credentials and no durable disk, so it seals a record here and hands the opaque bytes to its parent to
// keep. The parent needs no key — everything written through this module is already sealed (or, for `raw`, sealed to
// someone else) — so moving storage outside the enclave costs nothing in confidentiality and buys durability and
// scale. Absent ⇒ this backend does not exist and nothing changes.
const REMOTE = (process.env.MEMORY_REMOTE || '').replace(/\/$/, '')

// The S3 SDK is loaded LAZILY, at the first call that actually needs a bucket (MEMORY_BUCKET / TEMP_BUCKET /
// ENCLAVE_STORE_BUCKET): the enclave stores through MEMORY_REMOTE and never sets a bucket, so the SDK (~300 KB gzipped
// with @smithy) stays out of its measured payload — infra/enclave/prune.json; a static import here would fail its build.
let s3
const s3api = async () => {
  const m = await import('@aws-sdk/client-s3')
  return { client: (s3 ||= new m.S3Client(s3ClientOptions())), ...m }
}
// The local file for a stored object (its key, flattened) — used only when MEMORY_LOCAL_DIR is set.
const localPath = (key) => join(LOCAL_DIR, key.replace(/\//g, '__'))

/** Is memory persistence configured (S3, a local dir, or a remote store)? The KEY gates the read/write (hasMemoryKey). */
export const memoryEnabled = () => !!BUCKET || !!LOCAL_DIR || !!REMOTE

// ── The one place object I/O happens. Every caller above seals (or deliberately doesn't) and then goes through here,
// so a new backend is one branch rather than eight. Both throw on failure; callers already catch and fail soft.
async function writeObjectRaw(key, body) {
  if (REMOTE) {
    const r = await fetch(`${REMOTE}/put`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key, body }),
    })
    if (!r.ok) throw new Error(`remote put ${r.status}`)
    return true
  }
  if (LOCAL_DIR) {
    // ATOMIC, like an S3 PUT (2026-09-29): write beside it, then rename over. An in-place writeFile let a concurrent
    // reader see HALF a file — a torn read S3 can never produce — which made the dev store LESS faithful than the thing
    // it models: a racing approval read a torn doc, decoded it to nothing, and answered not_found.
    const p = localPath(key)
    await mkdir(dirname(p), { recursive: true })
    const tmp = `${p}.${process.pid}.${randomUUID()}.tmp`
    await writeFile(tmp, body)
    await rename(tmp, p)
    return true
  }
  const { client, PutObjectCommand } = await s3api()
  await client.send(new PutObjectCommand({ Bucket: bucketFor(key), Key: key, Body: body, ContentType: 'application/json' }))
  return true
}

// DEBUG_META (STAGING only, guarded by staging's OWN bucket · H19): drop a content-blind `<key>.meta.json` sidecar next
// to EVERY blob so the bucket is self-describing — its PURPOSE (derived from the key), size, and time (+ entry/turn
// counts for a ledger, read from the envelope shape). NEVER the mk or any plaintext (that would break E2EE). Best-effort;
// it never blocks or fails the real write, and it goes through writeObjectRaw so a sidecar is never itself sidecar'd.
const blobPurpose = (key) => {
  if (key.includes('/_ledger/')) return 'sealed chat ledger — v3 per-entry boxes (ciphertext; opens only with the room mk)'
  if (key.includes('/_partial/')) return 'in-progress reply — sealed streaming box (ephemeral; cleared when the turn lands)'
  if (key.includes('/_notif/')) return 'push preview sealed under NK=HKDF(mk,"notif") — Phase-4 rich notification (cannot open the ledger)'
  if (key.includes('/_devicecall/')) return 'parked client-tool call for the device (e.g. calendar) — sealed, opened by the client'
  if (key.startsWith('agent-memory/')) return 'agent living-call memory — verbatim event log, keyed by agent+room (sealed)'
  if (key.startsWith('llm-io/')) return 'LLM IO debug record — full model request+response (most sensitive; TTL-expired)'
  if (key.startsWith('memory/_raw_')) return 'durable raw Space doc'
  if (key.startsWith('memory/')) return 'durable Space doc'
  return 'blob'
}
const sidecarMeta = (key, body) => {
  const m = { v: 1, purpose: blobPurpose(key), key, bytes: (body || '').length, at: Date.now() }
  try { if (key.includes('/_ledger/')) { const j = JSON.parse(body); if (j && Array.isArray(j.boxes)) { m.format = j.v || 3; m.entries = j.boxes.length; if (Number.isInteger(j.done)) m.done = j.done } } } catch { /* not a v3 ledger */ }
  return m
}
async function writeObject(key, body) {
  const ok = await writeObjectRaw(key, body)
  if (DEBUG_META && typeof key === 'string' && !key.endsWith('.meta.json')) {
    try { await writeObjectRaw(key + '.meta.json', JSON.stringify(sidecarMeta(key, body))) } catch { /* debug sidecar is best-effort */ }
  }
  return ok
}

/** → the stored string. Throws when absent, matching what S3 and readFile already do; callers treat that as null. */
async function readObject(key) {
  if (REMOTE) {
    const r = await fetch(`${REMOTE}/get`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key }),
    })
    if (!r.ok) throw new Error(`remote get ${r.status}`)
    const j = await r.json()
    if (j.value == null) throw new Error('absent')
    return j.value
  }
  if (LOCAL_DIR) return readFile(localPath(key), 'utf8')
  const { client, GetObjectCommand } = await s3api()
  return (await client.send(new GetObjectCommand({ Bucket: bucketFor(key), Key: key }))).Body.transformToString()
}

// ── COMPARE-AND-SET I/O for the append-only ledger (appendLedger). `readObjectV` returns the body WITH a version tag
// (S3: the object's ETag; local dir: a hash of the bytes; remote: none — see below) and `writeObjectIf` writes only if
// the object still carries that tag (S3 `IfMatch`, or `IfNoneMatch:'*'` when the read found nothing), answering false on
// a conflict instead of throwing. This is what makes two writers appending at once BOTH land: the loser sees false,
// re-reads, and appends again behind the winner. Absent ⇒ `{ body: null, etag: null }`.
//   local dir: the tag is sha256(bytes) and the check-then-write runs under a per-key in-process lock — a faithful CAS
//              for one process, which is what dev and the tests are.
//   remote (the enclave's parent store, infra/enclave/parent_store.py): the parent's `/get` answers `{value, etag}` and
//              its `/put` takes `{cas:true, ifMatch}` — S3's own IfMatch/IfNoneMatch behind the wire, 412 on a conflict.
//              That is what makes the Lambda (writing a member's message straight to S3) and the enclave (writing the
//              turn's reply through the parent) two CONDITIONAL writers on one object instead of last-put-wins — the
//              enclave tier's lost-entry problem in [[spaces-enclave-rooms-lose-turns]]. Two older parents are still
//              served: one that answers 501 `cas_unsupported` (a boto3 too old for IfMatch) and one from before the
//              change (no etag on /get) — against those the client can only serialize ITS OWN writers, which it does
//              (the lock + a re-read-and-compare), so a burst from one enclave keeps every entry; a second process is
//              protected only once the parent is current.
const isAbsentErr = (e) => { const n = String((e && e.name) || ''); const c = (e && e.code) || (e && e.$metadata && e.$metadata.httpStatusCode) || ''; return String((e && e.message) || '') === 'absent' || c === 'ENOENT' || c === 404 || n === 'NoSuchKey' || n === 'NotFound' }
const isConflictErr = (e) => { const n = String((e && e.name) || ''); const c = (e && e.$metadata && e.$metadata.httpStatusCode) || 0; return n === 'PreconditionFailed' || n === 'ConditionalRequestConflict' || c === 412 || c === 409 }
const sha = (s) => createHash('sha256').update(String(s)).digest('base64')
const _keyLocks = new Map() // key → promise chain (local/remote only: the one-process lock)
const withKeyLock = (key, fn) => { const prev = _keyLocks.get(key) || Promise.resolve(); const next = prev.then(fn, fn); _keyLocks.set(key, next.catch(() => {})); return next }
let remoteTags = false // does the parent tag its objects? re-learned from every /get (the parent can be upgraded under a running enclave)
let remoteCasRefused = false // the parent answered 501 cas_unsupported (its S3 client is too old for IfMatch): sticky for this process
const LOCAL_TAG = 'local:' // a tag the client computed itself (sha of the bytes) because the parent gave none — never sent as ifMatch
const stripTag = (t) => (t == null ? null : String(t).replace(LOCAL_TAG, ''))
async function remoteGetV(key) {
  const r = await fetch(`${REMOTE}/get`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key }) })
  if (!r.ok) throw new Error(`remote get ${r.status}`)
  const j = await r.json()
  remoteTags = Object.prototype.hasOwnProperty.call(j, 'etag')
  const body = j.value == null ? null : j.value
  const wireTag = remoteTags && !remoteCasRefused && typeof j.etag === 'string' && j.etag ? j.etag : null
  const etag = body == null ? null : (wireTag || LOCAL_TAG + sha(body))
  return { body, etag }
}
async function readObjectV(key) {
  try {
    if (REMOTE) return remoteGetV(key)
    if (LOCAL_DIR) { const body = await readObject(key); return { body, etag: sha(body) } }
    const { client, GetObjectCommand } = await s3api()
    const r = await client.send(new GetObjectCommand({ Bucket: bucketFor(key), Key: key }))
    return { body: await r.Body.transformToString(), etag: r.ETag || null }
  } catch (e) { if (isAbsentErr(e)) return { body: null, etag: null }; throw e }
}
async function remotePutIf(key, body, etag) {
  const wireCas = remoteTags && !remoteCasRefused && !(etag && etag.startsWith(LOCAL_TAG))
  if (wireCas) {
    const r = await fetch(`${REMOTE}/put`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key, body, cas: true, ifMatch: etag || null }) })
    if (r.status === 412) return false
    if (r.status !== 501) {
      if (!r.ok) throw new Error(`remote put ${r.status}`)
      if (DEBUG_META && !key.endsWith('.meta.json')) { try { await writeObjectRaw(key + '.meta.json', JSON.stringify(sidecarMeta(key, body))) } catch { /* debug sidecar is best-effort */ } }
      return true
    }
    remoteCasRefused = true // the parent knows `cas` but its S3 client cannot express it: from here on, the one-process emulation
  }
  return withKeyLock(key, async () => {
    // the parent cannot check for us: re-read under the lock and compare the tags ourselves — a faithful CAS for this
    // process's writers, and the best a tagless wire allows. (Right after a 501 the tag we hold is the parent's and the
    // re-read's is ours: they differ, the caller re-reads, and the next attempt compares like with like.)
    const cur = await remoteGetV(key)
    if (stripTag(cur.etag) !== stripTag(etag)) return false
    return writeObject(key, body)
  })
}
/** → true (written) | false (someone else wrote first; re-read and try again). Throws on a real I/O failure. */
async function writeObjectIf(key, body, etag) {
  if (REMOTE) return remotePutIf(key, body, etag)
  if (LOCAL_DIR) {
    return withKeyLock(key, async () => {
      let cur = null; try { cur = sha(await readFile(localPath(key), 'utf8')) } catch (e) { if (!isAbsentErr(e)) throw e }
      if (cur !== etag) return false // absent ⇔ etag null; present ⇔ the tag of the bytes the caller read
      return writeObject(key, body)
    })
  }
  const { client, PutObjectCommand } = await s3api()
  try {
    await client.send(new PutObjectCommand({ Bucket: bucketFor(key), Key: key, Body: body, ContentType: 'application/json', ...(etag ? { IfMatch: etag } : { IfNoneMatch: '*' }) }))
  } catch (e) { if (isConflictErr(e)) return false; throw e }
  if (DEBUG_META && !key.endsWith('.meta.json')) { try { await writeObjectRaw(key + '.meta.json', JSON.stringify(sidecarMeta(key, body))) } catch { /* debug sidecar is best-effort */ } }
  return true
}

// Per-agent persistence gate (docs/encrypted-memory.md): an agent keeps state across sessions ONLY if its manifest
// declares `persistent` → launchAgent sets MEMORY_PERSISTENT=1. Not persistent ⇒ NO S3 read/write at all (in-session
// memory only), regardless of any key. The KEY (summoner mk / admin-derived beta key) only governs HOW it's sealed.
const PERSISTENT = process.env.MEMORY_PERSISTENT === '1'
// PROTOTYPE — v3 per-entry-sealed ledger WRITER. Default OFF: writes stay v2 whole-blob until the client v3 reader has
// saturated the field (emitting a slice to an old cached client would break it). When '1', an append seals only the NEW
// entries (O(1) crypto) and NEVER front-trims the STORED ledger (its box indices must stay stable for sinceCount polls).
// READERS (getLedger, pollSealedView) accept v3 regardless of this flag — so the flip is a writer-only switch.
const LEDGER_V3_WRITE = process.env.SPACE_LEDGER_V3 === '1'
export const ledgerV3WriteEnabled = () => LEDGER_V3_WRITE
const NOTIF_KEY_WRITE = process.env.NOTIF_KEY_WRITE === '1' // Phase-4 (docs/spaces-vault-architecture.md §07): store a per-entry NK-sealed preview so the SW composes a rich push without mk. Dormant until set.
const LEDGER_AAD_WRITE = process.env.LEDGER_AAD === '1' // M4: bind each new box to {room,index} via the GCM AAD (reorder/dup/replay detection). WRITER flag; readers self-adapt per box. Dormant until every reader is field-saturated, then flip.
const DEBUG_META = process.env.DEBUG_META === '1' // STAGING ONLY (guarded by its OWN bucket, H19): write a content-blind per-room metadata sidecar for debugging — STRUCTURAL facts only, NEVER the mk or any plaintext. Never set on prod.
export const memoryPersistent = () => PERSISTENT

// The room key is the shared single-source (roomKey.mjs); these names are kept for existing callers/tests.
// setMemoryKey sets the CREATOR key (onMemKey); the persist gate fires on ANY key (creator OR operator beta).
export const setMemoryKey = setRoomKey
export const hasMemoryKey = hasAnyKey

// Slugify a path segment so agent/room can NEVER traverse the key space (no "../", no control chars), bounded.
const slug = (s) =>
  String(s || '')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '_')
    .replace(/^\./, '_')
    .slice(0, 200) || 'x'

/** The S3 object key for a living call's memory. */
// ⚑ EPHEMERAL agent session memory lives under its OWN top-level prefix, deliberately NOT under memory/.
//
// It carries a 7-day TTL that is a PUBLISHED privacy commitment (docs/encrypted-memory.md: operator-
// readable, expires in 7 days), which means a lifecycle rule has to be able to reach it. Everything else
// this module writes — the Space ledger, the delegated-authority log, push subscriptions, widget state,
// out-of-line images — is DURABLE and must never expire.
//
// Those two lived under the same `memory/` prefix until 2026-08-01, when the 7-day rule was found to have
// deleted 895 durable objects (216 Spaces lost their entire history — test rooms, as it turned out, but the
// rule made no such distinction) to expire ONE ephemeral one. S3
// lifecycle filters have no NOT operator, so "memory/ except memory/_*" was not expressible and the rule
// had to be disabled outright, leaving the privacy commitment unenforced.
//
// Separate prefixes make the two structurally incapable of colliding: an expiry rule on `agent-memory/`
// cannot match `memory/…`, so the next durable doc filed under memory/ inherits NO rule rather than a
// silent 7-day timer. That is worth the IAM grant the original layout was written to avoid (memory.tf now
// grants agent-memory/* alongside memory/* and llm-io/*) — avoiding it is what caused the data loss.
export const memoryKey = (agentId, room) => `agent-memory/${slug(agentId)}/${slug(room)}.json`

// ── Pure seal/open glue (no S3) — tested directly ───────────────────────────────────────────────────────────
/** memory object → the sealed on-disk string, or null when there's NO room key (⇒ caller must NOT write). Sealed to
 *  the creator key (room) ONLY — platform-blind; no operator/admin recipient. */
export async function encodeMemory(memory, { mk = getRoomKey() } = {}) {
  if (!mk) return null // no room key → never write
  const env = await seal(JSON.stringify(memory), { mk })
  return JSON.stringify(env)
}
/** on-disk string → memory object, or null (no key / legacy plaintext / wrong key / tamper / malformed). Opens with
 *  the creator key (room recipient). */
export async function decodeMemory(stored, { mk = getRoomKey() } = {}) {
  if (!mk) return null
  let obj
  try {
    obj = JSON.parse(stored)
  } catch {
    return null
  }
  if (!isEnvelope(obj)) return null // legacy pre-encryption plaintext → ignore (ages out via TTL), resume clean
  const pt = await open(obj, { mk })
  if (pt == null) return null
  try {
    return JSON.parse(pt)
  } catch {
    return null
  }
}

/** Store the memory, SEALED under the room key (+ admin recipient on debug). No key ⇒ no write (fail-safe). */
export async function putMemory(agentId, room, memory) {
  if (!memoryEnabled() || !PERSISTENT) return false // not a persistent agent → never write (in-session only)
  try {
    const body = await encodeMemory(memory)
    if (body == null) return false // no room key → never persist (privacy-safe default)
    return await writeObject(memoryKey(agentId, room), body)
  } catch (e) {
    console.log('  memory store failed:', e && e.message)
    return false
  }
}

/** Fetch + DECRYPT a prior memory, or null (no key / none / legacy plaintext / unreadable → resume clean). */
export async function getMemory(agentId, room) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return null
  try {
    const stored = await readObject(memoryKey(agentId, room))
    return await decodeMemory(stored)
  } catch {
    return null // NoSuchKey / missing file / decode error → resume clean
  }
}

// ── Chat LEDGER (docs/chat-ledger.md, kibitz repo) — the DURABLE chat snapshot. ROOM-scoped (not agent-scoped like
// the memory above): the chat is the room's, not the agent's. Same seal/open + key gating; reuses encodeMemory/
// decodeMemory (a generic JSON seal). This is the Layer-2 durability: the agent persists the LEDGER, not a re-seed
// from its private event log.
// Under `memory/` (not a top-level `ledger/`) so it's covered by the agent's EXISTING S3 IAM (memory.tf grants
// memory/* + llm-io/* only — a top-level ledger/* would be AccessDenied, avoiding an IAM/terraform change). It sits
// in the agentId slot as `_ledger`, which no first-party agentId slugs to → no collision with an agent's own memory
// (memory/<agentId>/<room>.json). Still room-scoped (the chat is the room's), not agent-scoped.
export const ledgerKey = (room) => `memory/_ledger/${slug(room)}.json`
// v4 SEGMENTS (docs/ledger-segments.md). The WRITER flag only decides whether a v3 room is CONVERTED (or a rebuild writes
// v4); a room that is already v4 is always appended as v4, flag or not, and every reader below reads both.
const SEGMENTS_WRITE = process.env.LEDGER_SEGMENTS === '1'
const segKey = (room, gen, i) => `memory/_lseg_${gen}_${String(i).padStart(6, '0')}/${slug(room)}.json` // ends <room>.json: purge + lifecycle cover it
async function headEtag(key) {
  if (REMOTE || LOCAL_DIR) { const r = await readObjectV(key); return r.body == null ? null : r.etag }
  try { const { client, HeadObjectCommand } = await s3api(); return (await client.send(new HeadObjectCommand({ Bucket: bucketFor(key), Key: key }))).ETag || null }
  catch (e) { if (isAbsentErr(e)) return null; throw e }
}
const ledgerIo = (room) => ({ headerKey: ledgerKey(room), segKey: (gen, i) => segKey(room, gen, i), read: readObjectV, writeIf: writeObjectIf, head: headEtag })
/** The stored ledger body as every reader expects it: a v4 header is ASSEMBLED into the v3 shape { v:3, boxes, done };
 *  anything else is returned as stored. Throws when a v4 segment is missing — never a shorter room. */
async function assembleLedger(room, body) {
  const h = parseV4Header(body)
  if (!h) return body
  const all = await readAllSegments(ledgerIo(room), h)
  return JSON.stringify({ v: 3, boxes: all.boxes, ...(all.done !== undefined ? { done: all.done } : {}) })
}
// The IN-PROGRESS reply, so a reader can start reading before the turn finishes. Stored as an already-SEALED box and
// served verbatim: pollsealed is deliberately keyless, so the server must never be able to read this either. Separate
// from the ledger on purpose — the ledger stays append-only with exactly one final entry per turn, instead of the
// same box being rewritten a dozen times as text arrives.
export const partialKey = (room) => `memory/_partial/${slug(room)}.json`

// ★ TEMP-ROOM PURGE (the idle-wipe). Delete EVERY object a temporary room owns from TEMP_BUCKET. Two hard guards
// make this structurally incapable of touching durable data — the whole reason temp rooms are safe to auto-delete
// when normal rooms are not (agent/spacesReaper.mjs documents why normal-room deletion is deferred):
//   1. it REFUSES any room whose id is not `tmp-…` (isTempRoom), and
//   2. it ONLY ever lists/deletes TEMP_BUCKET — never MEMORY_BUCKET.
// TEMP_BUCKET is un-versioned (infra/temp-spaces.tf), so a delete frees the bytes with no noncurrent copy or
// delete-marker left behind. Keys are doc-first (`memory/_<doc>/<slug(room)>.json`), so we match by the exact room
// segment (the trailing basename minus extension) — a small dedicated bucket makes the sweep cheap.
// Does a TEMP_BUCKET object key belong to `room`? Matches BOTH key shapes that a temp room's blobs take:
//   • regular (Lambda sessionStore):  `memory/_<doc>/<slug(room)>.json`     → trailing basename === slug(room)
//   • enclave (parent-front FLATTENS): `memory__<doc>_<slug(room)>.json`    → room is the last `_`-segment
// `slug(tmp-<12 hex>)` is high-entropy, so `endsWith('_'+want)` can't collide with a different room. Pure + exported so
// the two-shape matching is unit-tested (a wrong matcher would either miss enclave blobs or over-delete a sibling).
export const tempKeyMatchesRoom = (key, room) => {
  const r = (String(key).split('/').pop() || '').replace(/\.meta\.json$/, '').replace(/\.json$/, '')
  const want = slug(room)
  return r === want || r.endsWith('_' + want)
}
export async function purgeRoom(room) {
  if (!TEMP_BUCKET || !isTempRoom(room)) return { skipped: true, deleted: 0 } // NEVER a durable room / durable bucket
  let token, deleted = 0
  const { client, ListObjectsV2Command, DeleteObjectsCommand } = await s3api()
  do {
    const list = await client.send(new ListObjectsV2Command({ Bucket: TEMP_BUCKET, ContinuationToken: token }))
    const victims = (list.Contents || []).filter((o) => tempKeyMatchesRoom(o.Key, room)).map((o) => ({ Key: o.Key }))
    for (let i = 0; i < victims.length; i += 1000) {
      const batch = victims.slice(i, i + 1000)
      if (batch.length) { await client.send(new DeleteObjectsCommand({ Bucket: TEMP_BUCKET, Delete: { Objects: batch, Quiet: true } })); deleted += batch.length }
    }
    token = list.IsTruncated ? list.NextContinuationToken : undefined
  } while (token)
  return { skipped: false, deleted }
}

/** Store the chat ledger snapshot, SEALED under the room key. No key / not persistent ⇒ no write (fail-safe). */
export async function putLedger(room, snapshot, opts = {}) {
  if (!memoryEnabled() || !PERSISTENT) return false
  if (LEDGER_V3_WRITE) return await putLedgerV3(room, snapshot, opts)
  try {
    const body = await encodeMemory(snapshot) // generic: seals JSON.stringify(snapshot) under the room key
    if (body == null) return false // no room key → never persist
    return await writeObject(ledgerKey(room), body)
  } catch (e) {
    console.log('  ledger store failed:', e && e.message)
    return false
  }
}

// v3 writer: append ONLY the new entries as per-entry sealed boxes (seal the delta, not the whole history — O(1) crypto).
// Migrates a v1/v2 blob to v3 on the first write (prevBoxes = [] ⇒ each entry sealed once). The caller passes the FULL
// desired snapshot (as it does today); we diff against the stored boxes and append the tail. If the snapshot is SHORTER
// than what we stored (a front-trim slipped through — under v3 the turn must NOT trim the STORED log, so its box indices
// stay stable for sinceCount polls), we rebuild rather than corrupt the append. No key ⇒ no write (fail-safe).
// `reseal` forces a full REBUILD (re-seal every entry) instead of the O(1) append. Needed when an ALREADY-published
// entry's content changed in place — e.g. a member photo gets its describe-once caption attached AFTER it was sealed in
// the early publish; the append path would keep the stale (caption-less) box forever. Entry order/indices are unchanged,
// so sinceCount polls are unaffected (same boxes count, re-encrypted plaintext-identical entries).
async function putLedgerV3(room, snapshot, { done, reseal } = {}) {
  const mk = getRoomKey()
  if (!mk) return false
  const entries = ledgerEntries(snapshot)
  if (!Array.isArray(entries)) return false
  try {
    let prevRaw = null
    try { prevRaw = await readObject(ledgerKey(room)) } catch { prevRaw = null } // fresh room → readObject throws ENOENT → no prior ledger
    if (prevRaw != null) prevRaw = await assembleLedger(room, prevRaw) // a v4 room: its boxes, assembled (a missing segment THROWS → no write)
    let prevBoxes = []
    let prevDone = null
    try { const p = JSON.parse(prevRaw); if (isV3(p)) { prevBoxes = p.boxes; if (Number.isInteger(p.done)) prevDone = p.done } } catch { /* v1/v2/absent → migrate (prevBoxes stays []) */ }
    // `done` = how many entries have been through a COMPLETED turn. Carried through when the caller does not
    // supply one, so an unrelated append (bridge crossing, import) cannot erase a resolution. MONOTONIC: a
    // peer hides its thinking indicator when this ADVANCES, so winding it back would re-arm every one of them.
    let nextDone = Number.isInteger(done) ? done : prevDone
    if (Number.isInteger(nextDone) && Number.isInteger(prevDone) && nextDone < prevDone) nextDone = prevDone
    const append = !reseal && entries.length >= prevBoxes.length // grew ⇒ append the tail; shrank/reseal ⇒ rebuild
    // ⚑ "nothing new" is NOT "nothing to do". A turn the agent answered with SILENCE appends no entry, and
    // recording that is the entire point — skip the write only when the resolution is unchanged too.
    // ⛔ THIS IS AN APPEND-ONLY WRITER, AND SAYING `true` HERE IS A PROMISE IT CANNOT KEEP FOR AN IN-PLACE EDIT.
    //    A caller that CHANGED an existing entry without adding one lands exactly here and is told the write
    //    succeeded. That cost every reaction in production: op:'react' mutated its target, called putLedger, got
    //    `true`, answered 200 with the new map — and the store was never touched. Reactions painted on tap and were
    //    gone on the next read, for months, with every test green because the suites run without SPACE_LEDGER_V3.
    //    ★ An in-place edit MUST use `rewriteLedgerEntries` (re-seals only the boxes named, keeps concurrent
    //      appends) or pass `{ reseal: true }` (rebuilds from the caller's log, drops concurrent appends). Both
    //      callers that were wrong — op:'react' and mirror's caption patch — are fixed in spaceService.mjs.
    if (append && entries.length === prevBoxes.length && nextDone === prevDone) return true
    // ⛔ THE APPEND GOES THROUGH THE COMPARE-AND-SET APPENDER (2026-09-29, a builder lost a row on the confidential tier).
    // This used to write `prevBoxes + tail` BLIND, so a box another writer appended between that read and this write was
    // overwritten. appendLedger re-reads on a conflict and lands the tail BEHIND whatever is stored by then. (A REBUILD —
    // reseal, or a snapshot that shrank — still replaces the ledger from the caller's log, as documented above.)
    if (append) {
      const ap = await appendLedger(room, entries.slice(prevBoxes.length), Number.isInteger(nextDone) ? { done: nextDone } : {})
      return !!(ap && ap.ok)
    }
    const boxes = append ? prevBoxes.slice() : []
    for (let i = append ? prevBoxes.length : 0; i < entries.length; i++) {
      // entries[i] always lands at ABSOLUTE box index i (append: boxes already = prevBoxes.slice(); reseal: boxes=[] from 0).
      const box = await sealEntry(entries[i], { mk, aad: LEDGER_AAD_WRITE ? ledgerAad(room, i) : null })
      if (box == null) return false
      boxes.push(box)
    }
    const body = SEGMENTS_WRITE // a REBUILD: a whole new generation, then the header (the old one is never referenced again)
      ? JSON.stringify(await writeGeneration(ledgerIo(room), boxes, Number.isInteger(nextDone) ? nextDone : undefined))
      : JSON.stringify({ v: 3, boxes, ...(Number.isInteger(nextDone) ? { done: nextDone } : {}) })
    const ok = await writeObject(ledgerKey(room), body)
    // Phase-4 (flag-gated): seal the NEWEST entry's preview under NK = HKDF(mk,'notif') so the Service Worker composes a
    // rich push WITHOUT the room mk. Only on a real new tail entry (never a reseal / no-op), best-effort — the ledger
    // write never fails for a notif error. NK can't open the ledger, so this stores no room-master authority.
    if (ok && NOTIF_KEY_WRITE && !reseal && entries.length > prevBoxes.length) {
      try { const env = await notifForEntry(mk, entries[entries.length - 1]); if (env) await putNotifRaw(room, env) } catch { /* best-effort */ }
    }
    return ok // DEBUG_META sidecar is now written generically for EVERY blob inside writeObject (the ledger's `<key>.meta.json` gets entries/done)
  } catch (e) {
    console.log('  v3 ledger store failed:', e && e.message)
    return false
  }
}

/** ★★ APPEND new entries to a room's ledger, SAFELY UNDER CONCURRENCY — the writer every caller should use for a new
 *  entry (2026-09-25). The snapshot writer above does read → append → unconditional write, and every caller built its
 *  snapshot from its own earlier read; so two writers in the same window overwrote each other, and a snapshot shorter
 *  than what was stored REBUILT the ledger without the other's entries. Measured by an outside builder from plain Node:
 *  30 writes at once → 5–7 kept, 30 fifty ms apart → 14–15 kept, each answered 200 with an entry id.
 *
 *  This one appends `entries` at the END OF WHATEVER IS STORED at the moment of the write: it reads the ledger with its
 *  version tag, seals each new entry at its absolute index (the AAD binds a box to that index), and writes CONDITIONALLY
 *  on the tag (S3 IfMatch / IfNoneMatch). A conflict means someone else appended meanwhile: re-read, re-seal behind
 *  them, write again — bounded, with jitter. Nothing a caller read earlier is ever written back, so nothing of anyone
 *  else's can be lost.
 *  `done`: 'all' ⇒ every entry stored after this append is marked as through a completed turn (monotonic; an integer
 *  is clamped to the count); absent ⇒ the stored marker is carried. An EMPTY `entries` with done:'all' just advances
 *  the marker. → { ok:true, count } (the ledger's length after the append) | { ok:false, reason }.
 *  Under the legacy (non-v3) writer this degrades to read-snapshot → append → putLedger, serialized in-process. */
export async function appendLedger(room, entries, { done, expectCount } = {}) {
  if (!memoryEnabled() || !PERSISTENT) return { ok: false, reason: 'no_store' }
  const mk = getRoomKey()
  if (!mk) return { ok: false, reason: 'no_key' }
  const add = Array.isArray(entries) ? entries.filter((e) => e && typeof e === 'object') : []
  if (!LEDGER_V3_WRITE) { // legacy whole-body writer: keep its semantics, just serialize the read-modify-write
    return withKeyLock(ledgerKey(room), async () => {
      let cur = []
      try { const d = await readLedgerDefinitive(room); if (d.ok) cur = d.entries } catch { /* absent/unreadable → start from what we have */ }
      if (Number.isInteger(expectCount) && cur.length !== expectCount) return { ok: false, reason: 'stale', count: cur.length }
      const next = [...cur, ...add]
      const ok = await putLedger(room, next, { ...(done === 'all' ? { done: next.length } : Number.isInteger(done) ? { done: Math.min(done, next.length) } : {}) })
      return ok ? { ok: true, count: next.length } : { ok: false, reason: 'write_failed' }
    })
  }
  const key = ledgerKey(room)
  const MAX_TRIES = 16
  for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
    let read
    try { read = await readObjectV(key) } catch (e) { return { ok: false, reason: 'read_failed', err: String((e && e.message) || e).slice(0, 120) } }
    const v4 = parseV4Header(read.body)
    if (v4) { // a SEGMENTED ledger: one CAS on the tail (or create the next segment) — never the whole history
      let r
      try { r = await appendOnce(ledgerIo(room), v4, read.etag, add, { seal: (e, i) => sealEntry(e, { mk, aad: LEDGER_AAD_WRITE ? ledgerAad(room, i) : null }), done, expectCount }) }
      catch (e) { return { ok: false, reason: 'write_failed', err: String((e && e.message) || e).slice(0, 120) } }
      if (r.ok) {
        if (NOTIF_KEY_WRITE && add.length) { try { const env = await notifForEntry(mk, add[add.length - 1]); if (env) await putNotifRaw(room, env) } catch { /* best-effort */ } }
        return r
      }
      if (r.reason === 'stale') return r
      await new Promise((res) => setTimeout(res, 5 + Math.floor(Math.random() * 25) * (1 + Math.min(attempt, 6))))
      continue
    }
    let prevBoxes = [], prevDone = null
    if (read.body != null) {
      let p = null; try { p = JSON.parse(read.body) } catch { p = null }
      if (isV3(p)) { prevBoxes = p.boxes; if (Number.isInteger(p.done)) prevDone = p.done }
      else if (read.body) {
        // A legacy v1/v2 blob: migrate it here, exactly as putLedgerV3 does — decode, seal every entry once at its index.
        let legacy = []
        try { legacy = ledgerEntries(await decodeMemory(read.body)) } catch { legacy = [] }
        if (!Array.isArray(legacy)) legacy = []
        prevBoxes = []
        for (let i = 0; i < legacy.length; i++) { const b = await sealEntry(legacy[i], { mk, aad: LEDGER_AAD_WRITE ? ledgerAad(room, i) : null }); if (b == null) return { ok: false, reason: 'seal_failed' }; prevBoxes.push(b) }
      }
    }
    // `expectCount`: the caller checked something about the ledger's CONTENT at N entries (a row's version, op:'data'
    // ifVersion) — if it has grown since, the check is stale: hand it back (`stale`, with the count) rather than append
    // behind writes it never saw. Plain appends never set it, so they keep landing behind concurrent writers.
    if (Number.isInteger(expectCount) && prevBoxes.length !== expectCount) return { ok: false, reason: 'stale', count: prevBoxes.length }
    const boxes = prevBoxes.slice()
    for (let j = 0; j < add.length; j++) {
      const box = await sealEntry(add[j], { mk, aad: LEDGER_AAD_WRITE ? ledgerAad(room, prevBoxes.length + j) : null })
      if (box == null) return { ok: false, reason: 'seal_failed' }
      boxes.push(box)
    }
    const count = boxes.length
    let nextDone = prevDone
    if (done === 'all') nextDone = count
    else if (Number.isInteger(done)) nextDone = Math.min(done, count)
    if (Number.isInteger(nextDone) && Number.isInteger(prevDone) && nextDone < prevDone) nextDone = prevDone // monotonic: a peer hides its thinking indicator when this advances
    if (!add.length && nextDone === prevDone && read.body != null && isV3(JSON.parse(read.body))) return { ok: true, count } // nothing to write
    let wrote = false
    try {
      // With the writer flag on, the room is CONVERTED here: its boxes (old + new) as a fresh generation, then the header
      // CAS'd over the v3 body it was read from — a concurrent v3 append makes it lose and retry, never overwrite.
      const body = SEGMENTS_WRITE
        ? JSON.stringify(await writeGeneration(ledgerIo(room), boxes, Number.isInteger(nextDone) ? nextDone : undefined))
        : JSON.stringify({ v: 3, boxes, ...(Number.isInteger(nextDone) ? { done: nextDone } : {}) })
      wrote = await writeObjectIf(key, body, read.etag)
    } catch (e) { return { ok: false, reason: 'write_failed', err: String((e && e.message) || e).slice(0, 120) } }
    if (wrote) {
      if (NOTIF_KEY_WRITE && add.length) { try { const env = await notifForEntry(mk, add[add.length - 1]); if (env) await putNotifRaw(room, env) } catch { /* best-effort */ } }
      return { ok: true, count }
    }
    await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 25) * (1 + Math.min(attempt, 6)))) // jittered backoff, then re-read behind the winner
  }
  console.log('  ledger append gave up after', MAX_TRIES, 'conflicts:', logRoom(room))
  return { ok: false, reason: 'conflict' }
}

/** Rewrite SPECIFIC entries of a stored v3 ledger IN PLACE — every other box stays byte-identical, in its index.
 *  `replace(entry, index)` returns the new entry, or a falsy value to keep the box as it is.
 *  Why not `putLedger(…, { reseal: true })`: a whole-ledger reseal rebuilds from the CALLER's in-memory log, so any box a
 *  concurrent writer appended meanwhile (another member's turn, a mirror, a bridge crossing) is dropped. The attachment
 *  migration (asyncTurn ↔ attachmentBlobs.mjs) runs for the length of a turn, so it must not widen that window: this
 *  reads the CURRENT stored ledger and touches only the boxes named, in a read→write of milliseconds. A legacy v1/v2
 *  blob is a no-op here — the next putLedger migrates it to v3 from the caller's (already migrated) log anyway.
 *  Returns the number of boxes rewritten (0 = nothing to do, or could not). */
export async function rewriteLedgerEntries(room, replace) {
  if (!memoryEnabled() || !PERSISTENT) return 0
  const mk = getRoomKey()
  if (!mk) return 0
  // ⛔ COMPARE-AND-SET, RETRIED (2026-09-29): this read the ledger, re-sealed the named boxes and wrote the whole thing
  // back BLIND — a box appended in between (a member's row, a reply) was overwritten. `replace` is re-applied to a fresh
  // read on each conflict, so it must be a pure function of the entry (every caller's is).
  for (let attempt = 0; attempt < 8; attempt++) {
  let read = null
  try { read = await readObjectV(ledgerKey(room)) } catch { return 0 }
  if (read.body == null) return 0
  const v4 = parseV4Header(read.body)
  if (v4) { // segment by segment, a CAS each — the other segments are never rewritten
    try {
      const n = await rewriteSegments(ledgerIo(room), v4, async (box, i) => {
        const aad = ledgerAad(room, i)
        const e = await openEntry(box, { mk, aad }); if (e == null) return null
        const next = await replace(e, i); if (!next) return null
        return sealEntry(next, { mk, aad: LEDGER_AAD_WRITE ? aad : null })
      })
      if (n) { try { await touchHeader(ledgerIo(room)) } catch { /* the edit stands; peers see it on the next change */ } } // the poll tag must move: peers refresh reactions on "changed, nothing new"
      return n
    } catch (e) { console.log('  ledger rewrite failed:', e && e.message); return 0 }
  }
  let p = null
  try { p = JSON.parse(read.body) } catch { return 0 }
  if (!isV3(p)) return 0
  const boxes = p.boxes.slice()
  let n = 0
  try {
    for (let i = 0; i < boxes.length; i++) {
      const aad = ledgerAad(room, i) // a bound box needs it; a legacy box ignores it
      const e = await openEntry(boxes[i], { mk, aad })
      if (e == null) continue
      const next = await replace(e, i)
      if (!next) continue
      const box = await sealEntry(next, { mk, aad: LEDGER_AAD_WRITE ? aad : null })
      if (box == null) return 0
      boxes[i] = box; n++
    }
    if (!n) return 0
    if (await writeObjectIf(ledgerKey(room), JSON.stringify({ ...p, boxes }), read.etag)) return n
  } catch (e) {
    console.log('  ledger rewrite failed:', e && e.message)
    return 0
  }
  await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 20) * (1 + Math.min(attempt, 4)))) // someone wrote first: re-read, re-apply
  }
  console.log('  ledger rewrite gave up after 8 conflicts:', logRoom(room))
  return 0
}

// ── LEDGER FORMAT VERSION ───────────────────────────────────────────────────────────────────────────
// The crypto is already versioned twice over (seal.mjs writes a version byte and refuses a mismatch;
// envelope.mjs stamps {v: VERSION} and isEnvelope checks it). What was never versioned is the PAYLOAD
// SHAPE — every ledger ever written is a bare JSON array of entries, and seven readers assert exactly
// that (six via getLedger, plus spaceClient.pollSealed in the browser).
//
// That matters more here than in an ordinary datastore, because the ledger is CIPHERTEXT the platform
// cannot read. There is no server-side backfill available, ever: no job we can write can open these
// blobs. So a format change can only be absorbed by READERS, and the shape must therefore be
// self-describing before it is ever allowed to change.
//
// v1 = a bare array (everything written to date). v2+ = { v, entries } — room for metadata beside the
// entries without another flag day.
//
// ⚑ PHASE 1 (this change): readers accept BOTH. Nothing writes v2 yet, so this is behaviour-neutral.
// ⚑ PHASE 2 (later, deliberate): flip the writer to emit { v: 2, entries }. It MUST NOT happen until
//    every client in the field tolerates it — spaceClient.pollSealed opens the blob in the BROWSER, and
//    those are cached PWAs behind a service worker. The gap is bounded by client rollover (days), not by
//    our deploy. Flipping the writer early breaks every stale tab with "couldn't unlock this Space".
export const LEDGER_FORMAT = 2

/** Normalise a decrypted ledger snapshot to the entries array, whichever format it was stored in.
 *  Returns null for absent/undecodable/unrecognised — every caller already treats null as "no ledger". */
export function ledgerEntries(snapshot) {
  if (Array.isArray(snapshot)) return snapshot // v1 — a bare array
  if (snapshot && typeof snapshot === 'object' && Array.isArray(snapshot.entries)) return snapshot.entries // v2+
  return null
}

/** Fetch + DECRYPT the chat ledger snapshot (the array of ledger items), or null. Callers get the ENTRIES
 *  array regardless of the stored format — this is the single server-side adapter for it. */
/** DEFINITIVE read: distinguishes "this room is empty" from "I could not read it".
 *
 * ⚠ THIS EXISTS BECAUSE THE AMBIGUITY DESTROYED DATA. `getLedger` returns null for FIVE different reasons — no
 * store, no key, genuinely empty, decrypt failure, or any throw — and only ONE of them means empty. Callers that
 * READ-THEN-WRITE collapsed all five to `[]`, appended their turn, and wrote that back AS THE WHOLE LEDGER. A
 * single failed read therefore replaced a room's history with one turn. Observed live 2026-09-08: a confidential
 * room's ledger went from 10 entries to 4 in eleven minutes, and the agent reported the Space as empty.
 *
 * The enclave tier hits it hardest — its read can fail at the sealed fetch, the KMS release, the mk unseal or the
 * decrypt, where the Lambda has only the last two.
 *
 * → { ok: true, entries }   safe to append and write back
 * → { ok: false, reason }   DO NOT WRITE. Fail the turn instead; a failed turn is recoverable, a clobbered ledger
 *                           is not. This is the "definitive-read guard" the index-clobber post-mortem asked for.
 */
export async function readLedgerDefinitive(room) {
  if (!memoryEnabled() || !PERSISTENT) return { ok: false, reason: 'no_store' }
  if (!hasAnyKey()) return { ok: false, reason: 'no_key' }
  // ★ ABSENT IS NOT A FAILURE, AND EVERY BACKEND SIGNALS IT BY THROWING: the remote store throws 'absent', a local
  // dir throws ENOENT, S3 throws NoSuchKey/NotFound. That is precisely why `getLedger`'s `catch → null` could never
  // tell "this room is new" from "I could not read it" — the two arrive by the same route. Classify them here.
  const isAbsent = (e) => {
    const name = String((e && e.name) || '')
    const msg = String((e && e.message) || '')
    const code = (e && e.code) || (e && e.$metadata && e.$metadata.httpStatusCode) || ''
    return msg === 'absent' || code === 'ENOENT' || code === 404 || name === 'NoSuchKey' || name === 'NotFound' || /\b404\b/.test(msg)
  }
  let stored
  try { stored = await readObject(ledgerKey(room)); if (stored != null) stored = await assembleLedger(room, stored) } // a missing v4 segment is read_failed below, never empty
  catch (e) {
    if (isAbsent(e)) return { ok: true, entries: [] }
    // CARRY THE ERROR. The first cut swallowed it and reported a bare 'read_failed', so when the guard fired on
    // every turn there was no way to tell WHICH error shape it had failed to classify. Never discard the evidence
    // that tells you why a fail-closed path is firing.
    return { ok: false, reason: 'read_failed', err: String((e && e.name) || '') + ':' + String((e && e.message) || e).slice(0, 120) }
  }
  if (stored == null) return { ok: true, entries: [] } // definitively empty
  let head = null
  try { head = JSON.parse(stored) } catch { /* legacy pre-encryption plaintext — decodeMemory handles it */ }
  try {
    const entries = isV3(head)
      ? await readLedgerEntries(stored, { mk: getRoomKey(), room })
      : ledgerEntries(await decodeMemory(stored))
    // Stored bytes exist but did not open ⇒ a decrypt/parse failure, NOT an empty room. Never let this look empty.
    if (!Array.isArray(entries)) return { ok: false, reason: 'decrypt_failed' }
    return { ok: true, entries }
  } catch (e) { return { ok: false, reason: 'decrypt_failed' } }
}

export async function getLedger(room) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return null
  try {
    const raw = await readObject(ledgerKey(room))
    const stored = raw == null ? raw : await assembleLedger(room, raw)
    if (stored == null) return null
    // v3 per-entry ledger → open each box; v1/v2 → decrypt the one blob (unchanged, null on failure). This reader
    // accepts v3 regardless of the write flag, so it's safe on a room already migrated by a peer/older deploy.
    let head = null
    try { head = JSON.parse(stored) } catch { /* legacy pre-encryption plaintext → decodeMemory handles it below */ }
    if (isV3(head)) return await readLedgerEntries(stored, { mk: getRoomKey(), room }) // room → the {room,index} aad for bound boxes (M4)
    return ledgerEntries(await decodeMemory(stored)) // generic: opens + JSON.parses → the snapshot, or null
  } catch {
    return null
  }
}

/** Fetch the RAW SEALED ledger string (ciphertext) — NO decrypt, NO key needed. The CONTENT-BLIND read the async-Space
 *  poll uses: the server returns this opaque blob + a change-tag, and the client decrypts it locally with mk (so a poll
 *  sends NO mk to the server). null when absent. Deliberately un-gated on the key — reading ciphertext reveals nothing. */
export async function getLedgerRaw(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const raw = await readObject(ledgerKey(room))
    return raw == null ? raw : await assembleLedger(room, raw)
  } catch {
    return null
  }
}

/** The raw sealed ledger WITH the store's own version tag → { body, tag }. `tag` is the S3 object ETag, and null on any
 *  other store (the enclave's parent, a local dir) — the poll then tags by sha256(body), as it always did. Absent ⇒
 *  { body: null, tag: null }. (2026-10-05: an unchanged poll no longer reads the body — see getLedgerTag.) */
export async function getLedgerRawV(room) {
  if (!memoryEnabled() || !PERSISTENT) return { body: null, tag: null }
  try {
    if (REMOTE || LOCAL_DIR) { const raw = await readObject(ledgerKey(room)); return { body: raw == null ? raw : await assembleLedger(room, raw), tag: null } }
    const { body, etag } = await readObjectV(ledgerKey(room))
    if (body == null) return { body, tag: null }
    const v4 = parseV4Header(body)
    if (!v4) return { body, tag: etag }
    const all = await readAllSegments(ledgerIo(room), v4) // the tag names the TAIL: an append changes only that segment
    return { body: JSON.stringify({ v: 3, boxes: all.boxes, ...(all.done !== undefined ? { done: all.done } : {}) }), tag: tagFromTail(etag, all.tail) }
  } catch {
    return { body: null, tag: null }
  }
}

/** The ledger's S3 ETag from a HEAD — no body read. null when the store has no cheap tag (remote / local) or the object
 *  is absent; the poll then falls back to reading the body. The ETag changes on every write, so equal tags = same bytes. */
export async function getLedgerTag(room) {
  if (!memoryEnabled() || !PERSISTENT || REMOTE || LOCAL_DIR) return null
  try {
    const { client, HeadObjectCommand } = await s3api()
    const key = ledgerKey(room)
    const h = await client.send(new HeadObjectCommand({ Bucket: bucketFor(key), Key: key }))
    if (!h.ETag) return null
    if (!(Number(h.ContentLength) <= 4096)) return h.ETag // a v4 header is tiny; a bigger object is a v3 ledger
    const r = await readObjectV(key) // small: read it to tell a v4 header from a short v3 ledger
    const v4 = parseV4Header(r.body)
    return v4 ? await tailTag(ledgerIo(room), r.etag, v4) : r.etag
  } catch {
    return null
  }
}

// The ENCLAVE persists via MEMORY_REMOTE → its parent (infra/enclave/parent-front.py) sanitises the key (any char
// outside [A-Za-z0-9._-] → '_', first 300) and stores the opaque body in ENCLAVE_STORE_BUCKET. So an enclave room's
// SEALED ledger sits there under the sanitised ledgerKey. This lets the RELAYING Lambda serve an ASLEEP enclave room's
// history content-blind from S3 (the client opens it with mk) — closing the "a never-cached asleep Space shows nothing"
// gap. Content-blind + read-only (ciphertext, no key): the Lambda never sees mk or plaintext, same trust as getLedgerRaw.
const ENCLAVE_STORE_BUCKET = process.env.ENCLAVE_STORE_BUCKET || ''
const enclaveStoreKey = (key) => String(key).slice(0, 300).replace(/[^A-Za-z0-9._-]/g, '_') // mirror parent-front's sanitiser EXACTLY
export async function getEnclaveLedgerRaw(room) {
  // §TEMP-ENCLAVE: a tmp- enclave room's sealed ledger lives in the no-backup TEMP_BUCKET (parent-front routed it there,
  // not the durable enclave store) — read from the right bucket. The flattened key is identical either way.
  const b = isTempRoom(room) ? TEMP_BUCKET : ENCLAVE_STORE_BUCKET
  if (!b) return null
  try {
    const { client, GetObjectCommand } = await s3api()
    const read = async (key) => {
      try { const r = await client.send(new GetObjectCommand({ Bucket: b, Key: enclaveStoreKey(key) })); return { body: await r.Body.transformToString(), etag: r.ETag || null } }
      catch (e) { if (isAbsentErr(e)) return { body: null, etag: null }; throw e }
    }
    const { body } = await read(ledgerKey(room))
    const v4 = parseV4Header(body)
    if (!v4) return body
    // a SEGMENTED confidential ledger: the same segments, under the parent's flattened keys (read-only here)
    const all = await readAllSegments({ headerKey: ledgerKey(room), segKey: (gen, i) => segKey(room, gen, i), read }, v4)
    return JSON.stringify({ v: 3, boxes: all.boxes, ...(all.done !== undefined ? { done: all.done } : {}) })
  } catch {
    return null // NoSuchKey / absent → no stored ledger (same as getLedgerRaw)
  }
}

// ── Generic room-scoped SEALED doc (a NAMED sibling of the ledger) — for async-Space side docs like the delegated-
// authority proposals + audit log. Same seal/open + key gating as the ledger; a distinct `name` → a distinct key under
// memory/ (so the agent's existing S3 IAM covers it). name is slugged; no first-party agentId collides with `_<name>`.
const docKey = (room, name) => `memory/_${slug(name)}/${slug(room)}.json`
/** Store a named room doc, SEALED under the room key. No key / not persistent ⇒ no write (fail-safe). */
/** Write the sealed partial for a room. `box` is an already-sealed envelope string; null clears it. */
// `status` (optional) is a SECOND sealed box: what the turn is doing right now — working, a named tool, writing — so a
// reader sees progress before the first word of the answer (docs/turn-progress.md). It rides the same record, so it
// costs no extra read on the poll, and a record may carry a status with no text yet (`box` absent). A client that
// predates it never sees it: the poll passes it through as its own field, and `partial` only ever carries text.
export async function putPartial(room, box, seq = 0, status = null) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    if (box == null && !status) return await writeObject(partialKey(room), JSON.stringify({ v: 1, cleared: true, seq }))
    return await writeObject(partialKey(room), JSON.stringify({ v: 1, ...(box != null ? { box } : {}), ...(status ? { status } : {}), seq, at: Date.now() }))
  } catch { return false }
}
/** Read the partial VERBATIM — no decryption; the client opens the box with mk. */
export async function getPartialRaw(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const raw = await readObject(partialKey(room))
    if (!raw) return null
    const o = JSON.parse(raw)
    return o && !o.cleared && (o.box || o.status) ? { box: o.box || null, seq: o.seq || 0, at: o.at || 0, status: o.status || null } : null
  } catch { return null }
}

// ── STOP signal — a per-room, per-turn CANCEL marker. The client that prompted holds a random `stopKey` (sent with the
// turn, never stored in the ledger); a stop request writes it here, and the RUNNING turn (a DIFFERENT invocation) polls
// this marker and aborts the model call only when the key matches ITS OWN stopKey. That per-turn nonce is the whole auth
// model — "only the one that prompted can stop it" — and makes stop concurrency-safe (it targets exactly one turn).
// PLAINTEXT by design: the key is a random nonce (no content, not derived from mk), so it reveals nothing at rest.
const stopSigKey = (room) => `memory/_stop/${slug(room)}.json`
export async function putStopSig(room, sig) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    if (sig == null) return await writeObject(stopSigKey(room), JSON.stringify({ v: 1, cleared: true }))
    return await writeObject(stopSigKey(room), JSON.stringify({ v: 1, key: String(sig.key || '').slice(0, 64), at: sig.at || Date.now() }))
  } catch { return false }
}
export async function getStopSig(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const raw = await readObject(stopSigKey(room))
    if (!raw) return null
    const o = JSON.parse(raw)
    return o && o.key && !o.cleared ? { key: o.key, at: o.at || 0 } : null
  } catch { return null }
}

// ── TURN-IN-PROGRESS flag (docs/spaces-turn-queue.md) — "one voice, in order". A turn STAMPS this at start and CLEARS it
// at end; a turn arriving while a FRESH flag is present is told to QUEUE (its client resends when the current reply
// lands). Best-effort serialization (a store race can let two through → falls back to the pre-existing concurrent
// behaviour, never worse). Plaintext (just a timestamp — no content). The reader treats a flag older than the TTL as
// STALE so a crashed/timed-out turn can never wedge the room.
const turnFlagKey = (room) => `memory/_turnflag/${slug(room)}.json`
export async function putTurnFlag(room, flag) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    if (flag == null) return await writeObject(turnFlagKey(room), JSON.stringify({ v: 1, cleared: true }))
    return await writeObject(turnFlagKey(room), JSON.stringify({ v: 1, at: flag.at || Date.now() }))
  } catch { return false }
}
export async function getTurnFlag(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const raw = await readObject(turnFlagKey(room))
    if (!raw) return null
    const o = JSON.parse(raw)
    return o && o.at && !o.cleared ? { at: o.at } : null
  } catch { return null }
}

// ── THE TURN LEASE (the independent review, 2026-10-05, finding 4). The flag above was read, then written: two turns that
// read "no flag" in the same window both ran (reproduced: two at once, both started). A lease is taken with the store's
// compare-and-set (S3 IfNoneMatch/IfMatch, the parent's cas wire, a per-key lock locally) — of N callers in one window,
// exactly one writes it — and carries an OWNER, so only the turn that took it clears it (an old turn's late clear can
// no longer free a newer turn's claim). It outlives the longest turn: the Lambda's 300 s timeout (the turn budget is
// 240 s, the enclave's kill 260 s), so a live turn never loses it and a crashed one frees the room within ~5½ minutes.
// Same object as the flag (`memory/_turnflag/<room>.json`), so getTurnFlag still reads it.
export const TURN_LEASE_MS = 330000
/** → { ok:true } (the lease is yours) | { ok:false, busy:true } (a live turn holds it) | { ok:false, reason } (no store
 *  answer — the caller decides; the transport lets the turn run, as the flag always did on a store failure). */
export async function acquireTurnLease(room, { owner, now = Date.now(), ttlMs = TURN_LEASE_MS } = {}) {
  if (!memoryEnabled() || !PERSISTENT) return { ok: true, noStore: true }
  const key = turnFlagKey(room)
  for (let i = 0; i < 4; i++) {
    let cur
    try { cur = await readObjectV(key) } catch (e) { return { ok: false, reason: 'read_failed', err: String((e && e.message) || e).slice(0, 120) } }
    let o = null; try { o = cur.body ? JSON.parse(cur.body) : null } catch { o = null }
    if (o && o.at && !o.cleared && now - o.at < ttlMs) return { ok: false, busy: true }
    let won
    try { won = await writeObjectIf(key, JSON.stringify({ v: 2, at: now, owner: String(owner || '') }), cur.etag) } catch (e) { return { ok: false, reason: 'write_failed', err: String((e && e.message) || e).slice(0, 120) } }
    if (won) return { ok: true }
    // someone wrote between our read and our write: re-read — it is almost always their fresh lease (→ busy)
  }
  return { ok: false, busy: true }
}
/** Clear the lease ONLY if `owner` still holds it (compare-and-set on what we read). Best-effort: the TTL frees it anyway. */
export async function releaseTurnLease(room, owner) {
  if (!memoryEnabled() || !PERSISTENT) return false
  const key = turnFlagKey(room)
  try {
    const cur = await readObjectV(key)
    let o = null; try { o = cur.body ? JSON.parse(cur.body) : null } catch { o = null }
    if (!o || o.cleared || o.owner !== String(owner || '')) return false
    return await writeObjectIf(key, JSON.stringify({ v: 2, cleared: true }), cur.etag)
  } catch { return false }
}

// ── ONE-TIME CLAIMS for a signed or challenged turn (finding 4, the replay half). The ledger check ("is this id already
// stored?") reads a snapshot, so two copies of one signed message sent at once both passed it and both ran the model.
// Before the model runs, the turn now CLAIMS its id in the room's sealed claims doc with compare-and-set: one copy adds
// it, the other finds it there. Bounded (the newest CLAIMS_MAX ids — a challenge's TTL and a signed turn's ts bound how
// far back a replay can come from; the ledger check stays as the long-memory backstop). → true (claimed) | false (taken).
// Throws when the store cannot answer: the caller refuses rather than run unclaimed.
const CLAIMS_DOC = 'turnclaims'
const CLAIMS_MAX = 500
export async function claimTurnId(room, id) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return true // nothing is stored on this tier — nothing to replay against
  return updateDoc(room, CLAIMS_DOC, (cur) => {
    const ids = Array.isArray(cur && cur.ids) ? cur.ids : []
    if (ids.includes(id)) return { value: false }
    return { doc: { v: 1, ids: [...ids, id].slice(-CLAIMS_MAX) }, value: true }
  })
}

// ── NOTIFICATION-ONLY-KEY preview (Phase 4) — the newest entry sealed under NK=HKDF(mk,'notif'), stored VERBATIM so the
// Service Worker composes a push preview WITHOUT the room mk. Content-blind: NK cannot open the ledger. Mirrors the partial.
const notifRawKey = (room) => `memory/_notif/${slug(room)}.json`
export async function putNotifRaw(room, env) {
  if (!memoryEnabled() || !PERSISTENT || !env) return false
  try { return await writeObject(notifRawKey(room), JSON.stringify({ v: 1, notif: env, at: Date.now() })) } catch { return false }
}
/** Read the notif preview VERBATIM — no decryption; the SW opens it with the mirrored NK. */
export async function getNotifRaw(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try { const raw = await readObject(notifRawKey(room)); if (!raw) return null; const o = JSON.parse(raw); return o && o.notif ? o.notif : null } catch { return null }
}

// ── Device-call box (MIRRORS the partial) — a per-room parked request from the turn Lambda to the member's DEVICE: a
// client-executed tool (the personal calendar, which is E2EE/local — the server has no copy) that the browser must run
// against its own data. `box` is sealed under mk; the client opens it, runs the tool, and posts the sealed result back
// (op:'toolresult' → putRaw). null clears it. Singleton per room (like partial) → reads run sequentially.
const deviceCallKey = (room) => `memory/_devicecall/${slug(room)}.json`
export async function putDeviceCall(room, box, seq = 0) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    if (box == null) return await writeObject(deviceCallKey(room), JSON.stringify({ v: 1, cleared: true, seq }))
    return await writeObject(deviceCallKey(room), JSON.stringify({ v: 1, box, seq, at: Date.now() }))
  } catch { return false }
}
/** Read the parked device call VERBATIM — no decryption; the client opens the box with mk. */
export async function getDeviceCallRaw(room) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const raw = await readObject(deviceCallKey(room))
    if (!raw) return null
    const o = JSON.parse(raw)
    return o && o.box && !o.cleared ? { box: o.box, seq: o.seq || 0, at: o.at || 0 } : null
  } catch { return null }
}

export async function putDoc(room, name, snapshot) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    const body = await encodeMemory(snapshot)
    if (body == null) return false // no room key → never persist
    return await writeObject(docKey(room, name), body)
  } catch (e) {
    console.log(`  doc(${name}) store failed:`, e && e.message)
    return false
  }
}
/**
 * READ → CHANGE → WRITE-ONLY-IF-UNCHANGED for a sealed room doc, retried on a conflict. `mutate(current|null)` returns
 * `{ doc, value }`: `doc` is the new snapshot to store (omit it to write nothing), `value` is what updateDoc resolves to.
 * `mutate` may run MORE THAN ONCE (each conflict re-reads and re-applies), so it must derive everything from its argument.
 * ⛔ WHY (2026-09-29): putDoc is last-write-wins over the WHOLE doc. The `authority` doc (proposals + approvals + audit)
 * had three writers doing load → change → putDoc, and a builder who approves from INSIDE a turn that is still proposing
 * lost ~1 approval in 9: the turn wrote back its stale copy over the approval. This is the ledger's compare-and-set
 * (readObjectV / writeObjectIf — S3 IfMatch, the parent's cas wire, a per-key lock locally) applied to a doc.
 * ⚑ A doc that exists but opens to null (legacy plaintext, a foreign seal) is treated as ABSENT and replaced — the same
 *   "resume clean" rule getDoc → putDoc always applied. Only the RACE is new here, not the recovery policy.
 */
export async function updateDoc(room, name, mutate, { attempts = 8 } = {}) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return (await mutate(null)).value // nothing is persisted on this tier: same as getDoc → null
  const key = docKey(room, name)
  for (let i = 0; i < attempts; i++) {
    const { body, etag } = await readObjectV(key)
    let cur = null
    if (body != null) cur = await decodeMemory(body) // null when it cannot be opened ⇒ resume clean, as getDoc does
    const { doc, value } = await mutate(cur)
    if (doc === undefined) return value
    const out = await encodeMemory(doc)
    if (out == null) return value // no room key → never persist (putDoc's rule)
    if (await writeObjectIf(key, out, etag)) return value
    await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 20) * (1 + Math.min(i, 4)))) // someone wrote first: re-read, re-apply
  }
  throw new Error(`doc(${name}) busy: ${attempts} conflicting writers in a row`)
}
/** Fetch + DECRYPT a named room doc, or null. */
export async function getDoc(room, name) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return null
  try {
    const stored = await readObject(docKey(room, name))
    return await decodeMemory(stored)
  } catch {
    return null
  }
}
/** getDoc that tells ABSENT from UNAVAILABLE: never written → null; the store could not answer → throws (code
 *  'store_unavailable'). getDoc's `catch → null` made a store outage read as an empty doc, and op:'state' then wrote a
 *  device's partial copy over the real one (a reviewer's finding, 2026-10-05; agent/stateStoreDown.test.mjs). A doc that
 *  exists but does not open is still null, as in getDoc. */
/** Is there a durable doc store at all? Without one putDoc answers false by design (dev/no-storage), which is not an outage. */
export const docStoreOn = () => memoryEnabled() && PERSISTENT
export async function getDocStrict(room, name) {
  if (!memoryEnabled() || !PERSISTENT || !hasAnyKey()) return null
  let stored
  try { stored = await readObject(docKey(room, name)) } catch (e) {
    if (isAbsentErr(e)) return null
    const err = new Error('store_unavailable: ' + ((e && e.message) || e)); err.code = 'store_unavailable'; throw err
  }
  try { return await decodeMemory(stored) } catch { return null }
}

// ── Content-blind RAW doc — a named room doc stored AS-IS (no mk sealing, no key gating). For an agent's scoped view:
// the value is ALREADY a sealed box to the agent's own key (envelope.sealTo), so it's opaque to the platform and safe
// to store + serve in the clear. An agent holds NO mk, so it fetches its view via getRaw (ungated) and opens it with
// its own box key. Distinct key prefix (memory/_raw_*) so the agent's existing S3 IAM (memory/*) covers it.
const rawKey = (room, name) => `memory/_raw_${slug(name)}/${slug(room)}.json`
/** Store a self-sealed blob AS-IS (JSON if not already a string). No key needed — the blob protects itself. */
export async function putRaw(room, name, value) {
  if (!memoryEnabled() || !PERSISTENT) return false
  try {
    const body = typeof value === 'string' ? value : JSON.stringify(value)
    return await writeObject(rawKey(room, name), body)
  } catch (e) {
    console.log(`  raw(${name}) store failed:`, e && e.message)
    return false
  }
}
/** Fetch a raw blob (parsed JSON, else the string), or null. UN-gated on the key — the blob is opaque ciphertext. */
export async function getRaw(room, name) {
  if (!memoryEnabled() || !PERSISTENT) return null
  try {
    const s = await readObject(rawKey(room, name))
    try { return JSON.parse(s) } catch { return s }
  } catch {
    return null
  }
}
