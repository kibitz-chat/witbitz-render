// Session-memory store (docs/agent-persistence.md, brick 4; sealing per docs/encrypted-memory.md). Stores a living
// call's memory to S3 keyed by agent+room and fetches it back on resume. PLATFORM-BLIND: the blob is SEALED with
// the room key (mk) the agent received over E2EE — the operator sees ciphertext only. FAIL-SAFE: no mk ⇒ nothing is
// written or read (in-session memory only) — strictly better than the old plaintext-always default, and the safe
// behavior for clients that don't deliver a key. FAIL-SOFT: any S3 error → start/leave clean; never crash the call.
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { seal, open, isEnvelope } from './envelope.mjs'
import { getRoomKey, setRoomKey, getBetaKey, hasAnyKey } from './roomKey.mjs'

const BUCKET = process.env.MEMORY_BUCKET || ''
const REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'eu-central-1'
// DEV/E2E: a local directory to store the SEALED memory blob instead of S3 — fully-local persistence (no AWS), so a
// resume round-trip can be exercised on one box. Same seal/open + key gating as S3; only the object I/O differs.
const LOCAL_DIR = process.env.MEMORY_LOCAL_DIR || ''
// DEBUG-only: an offline admin PUBLIC key (SPKI PEM/base64) injected into debug tasks → a 2nd envelope recipient so
// the operator can decrypt offline. Absent on NORMAL tasks → room-only (operator-blind). Wired in P3.
const ADMIN_PUB = process.env.MEMORY_ADMIN_PUBKEY || ''
let s3
const client = () => (s3 ||= new S3Client({ region: REGION }))
// The local file for a room's sealed memory (S3 key flattened) — used only when MEMORY_LOCAL_DIR is set.
const localPath = (agentId, room) => join(LOCAL_DIR, memoryKey(agentId, room).replace(/\//g, '__'))

/** Is memory persistence configured (an S3 bucket OR a local dir)? The KEY gates the actual read/write (hasMemoryKey). */
export const memoryEnabled = () => !!BUCKET || !!LOCAL_DIR

// Per-agent persistence gate (docs/encrypted-memory.md): an agent keeps state across sessions ONLY if its manifest
// declares `persistent` → launchAgent sets MEMORY_PERSISTENT=1. Not persistent ⇒ NO S3 read/write at all (in-session
// memory only), regardless of any key. The KEY (summoner mk / admin-derived beta key) only governs HOW it's sealed.
const PERSISTENT = process.env.MEMORY_PERSISTENT === '1'
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
export const memoryKey = (agentId, room) => `memory/${slug(agentId)}/${slug(room)}.json`

// ── Pure seal/open glue (no S3) — tested directly ───────────────────────────────────────────────────────────
/** memory object → the sealed on-disk string, or null when there's NO recipient (⇒ caller must NOT write). Sealed
 *  to the creator key (room), the operator beta key (beta), and/or the debug admin key — dual-recipient, so a gift
 *  stays operator-readable while beta is on AND creator-openable via mk. */
export async function encodeMemory(memory, { mk = getRoomKey(), betaMk = getBetaKey(), adminPubKey = ADMIN_PUB } = {}) {
  if (!mk && !betaMk && !adminPubKey) return null // no recipient → never write
  const env = await seal(JSON.stringify(memory), { ...(mk ? { mk } : {}), ...(betaMk ? { betaMk } : {}), ...(adminPubKey ? { adminPubKey } : {}) })
  return JSON.stringify(env)
}
/** on-disk string → memory object, or null (no key / legacy plaintext / wrong key / tamper / malformed). Tries the
 *  creator key first, then the operator beta key — so the agent resumes whichever recipient the record carries. */
export async function decodeMemory(stored, { mk = getRoomKey(), betaMk = getBetaKey() } = {}) {
  if (!mk && !betaMk) return null
  let obj
  try {
    obj = JSON.parse(stored)
  } catch {
    return null
  }
  if (!isEnvelope(obj)) return null // legacy pre-encryption plaintext → ignore (ages out via TTL), resume clean
  let pt = mk ? await open(obj, { mk }) : null
  if (pt == null && betaMk) pt = await open(obj, { mk: betaMk })
  if (pt == null) return null
  try {
    return JSON.parse(pt)
  } catch {
    return null
  }
}

/** Store the memory, SEALED under the room key (+ admin recipient on debug). No key ⇒ no write (fail-safe). */
export async function putMemory(agentId, room, memory) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return false // not a persistent agent → never write (in-session only)
  try {
    const body = await encodeMemory(memory)
    if (body == null) return false // no room key → never persist (privacy-safe default)
    if (LOCAL_DIR) {
      const p = localPath(agentId, room)
      await mkdir(dirname(p), { recursive: true })
      await writeFile(p, body)
      return true
    }
    await client().send(new PutObjectCommand({ Bucket: BUCKET, Key: memoryKey(agentId, room), Body: body, ContentType: 'application/json' }))
    return true
  } catch (e) {
    console.log('  memory store failed:', e && e.message)
    return false
  }
}

/** Fetch + DECRYPT a prior memory, or null (no key / none / legacy plaintext / unreadable → resume clean). */
export async function getMemory(agentId, room) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT || !hasAnyKey()) return null
  try {
    const stored = LOCAL_DIR
      ? await readFile(localPath(agentId, room), 'utf8')
      : await (await client().send(new GetObjectCommand({ Bucket: BUCKET, Key: memoryKey(agentId, room) }))).Body.transformToString()
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
const ledgerLocalPath = (room) => join(LOCAL_DIR, ledgerKey(room).replace(/\//g, '__'))

/** Store the chat ledger snapshot, SEALED under the room key. No key / not persistent ⇒ no write (fail-safe). */
export async function putLedger(room, snapshot) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return false
  try {
    const body = await encodeMemory(snapshot) // generic: seals JSON.stringify(snapshot) under the room key
    if (body == null) return false // no room key → never persist
    if (LOCAL_DIR) {
      const p = ledgerLocalPath(room)
      await mkdir(dirname(p), { recursive: true })
      await writeFile(p, body)
      return true
    }
    await client().send(new PutObjectCommand({ Bucket: BUCKET, Key: ledgerKey(room), Body: body, ContentType: 'application/json' }))
    return true
  } catch (e) {
    console.log('  ledger store failed:', e && e.message)
    return false
  }
}

/** Fetch + DECRYPT the chat ledger snapshot (the array of ledger items), or null. */
export async function getLedger(room) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT || !hasAnyKey()) return null
  try {
    const stored = LOCAL_DIR
      ? await readFile(ledgerLocalPath(room), 'utf8')
      : await (await client().send(new GetObjectCommand({ Bucket: BUCKET, Key: ledgerKey(room) }))).Body.transformToString()
    return await decodeMemory(stored) // generic: opens + JSON.parses → the snapshot, or null
  } catch {
    return null
  }
}

/** Fetch the RAW SEALED ledger string (ciphertext) — NO decrypt, NO key needed. The CONTENT-BLIND read the async-Space
 *  poll uses: the server returns this opaque blob + a change-tag, and the client decrypts it locally with mk (so a poll
 *  sends NO mk to the server). null when absent. Deliberately un-gated on the key — reading ciphertext reveals nothing. */
export async function getLedgerRaw(room) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return null
  try {
    return LOCAL_DIR
      ? await readFile(ledgerLocalPath(room), 'utf8')
      : await (await client().send(new GetObjectCommand({ Bucket: BUCKET, Key: ledgerKey(room) }))).Body.transformToString()
  } catch {
    return null
  }
}

// ── Generic room-scoped SEALED doc (a NAMED sibling of the ledger) — for async-Space side docs like the delegated-
// authority proposals + audit log. Same seal/open + key gating as the ledger; a distinct `name` → a distinct key under
// memory/ (so the agent's existing S3 IAM covers it). name is slugged; no first-party agentId collides with `_<name>`.
const docKey = (room, name) => `memory/_${slug(name)}/${slug(room)}.json`
const docLocalPath = (room, name) => join(LOCAL_DIR, docKey(room, name).replace(/\//g, '__'))
/** Store a named room doc, SEALED under the room key. No key / not persistent ⇒ no write (fail-safe). */
export async function putDoc(room, name, snapshot) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return false
  try {
    const body = await encodeMemory(snapshot)
    if (body == null) return false // no room key → never persist
    if (LOCAL_DIR) {
      const p = docLocalPath(room, name)
      await mkdir(dirname(p), { recursive: true })
      await writeFile(p, body)
      return true
    }
    await client().send(new PutObjectCommand({ Bucket: BUCKET, Key: docKey(room, name), Body: body, ContentType: 'application/json' }))
    return true
  } catch (e) {
    console.log(`  doc(${name}) store failed:`, e && e.message)
    return false
  }
}
/** Fetch + DECRYPT a named room doc, or null. */
export async function getDoc(room, name) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT || !hasAnyKey()) return null
  try {
    const stored = LOCAL_DIR
      ? await readFile(docLocalPath(room, name), 'utf8')
      : await (await client().send(new GetObjectCommand({ Bucket: BUCKET, Key: docKey(room, name) }))).Body.transformToString()
    return await decodeMemory(stored)
  } catch {
    return null
  }
}

// ── Content-blind RAW doc — a named room doc stored AS-IS (no mk sealing, no key gating). For an agent's scoped view:
// the value is ALREADY a sealed box to the agent's own key (envelope.sealTo), so it's opaque to the platform and safe
// to store + serve in the clear. An agent holds NO mk, so it fetches its view via getRaw (ungated) and opens it with
// its own box key. Distinct key prefix (memory/_raw_*) so the agent's existing S3 IAM (memory/*) covers it.
const rawKey = (room, name) => `memory/_raw_${slug(name)}/${slug(room)}.json`
const rawLocalPath = (room, name) => join(LOCAL_DIR, rawKey(room, name).replace(/\//g, '__'))
/** Store a self-sealed blob AS-IS (JSON if not already a string). No key needed — the blob protects itself. */
export async function putRaw(room, name, value) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return false
  try {
    const body = typeof value === 'string' ? value : JSON.stringify(value)
    if (LOCAL_DIR) {
      const p = rawLocalPath(room, name)
      await mkdir(dirname(p), { recursive: true })
      await writeFile(p, body)
      return true
    }
    await client().send(new PutObjectCommand({ Bucket: BUCKET, Key: rawKey(room, name), Body: body, ContentType: 'application/json' }))
    return true
  } catch (e) {
    console.log(`  raw(${name}) store failed:`, e && e.message)
    return false
  }
}
/** Fetch a raw blob (parsed JSON, else the string), or null. UN-gated on the key — the blob is opaque ciphertext. */
export async function getRaw(room, name) {
  if ((!BUCKET && !LOCAL_DIR) || !PERSISTENT) return null
  try {
    const s = LOCAL_DIR
      ? await readFile(rawLocalPath(room, name), 'utf8')
      : await (await client().send(new GetObjectCommand({ Bucket: BUCKET, Key: rawKey(room, name) }))).Body.transformToString()
    try { return JSON.parse(s) } catch { return s }
  } catch {
    return null
  }
}
