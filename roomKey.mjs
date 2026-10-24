// The sealing keys for agent memory — the SINGLE source of truth shared by the session memory (sessionStore.mjs)
// and the LLM-IO debug records (llmLog.mjs). Held only in volatile RAM; never logged or written.
//   - room key (mk): the CREATOR's platform-blind key, delivered over E2EE and accepted only if it matches the
//     summon's commitment (agent.mjs onMemKey, docs/encrypted-memory.md). The operator never sees it. It is the ONLY
//     sealing key — there is no operator recipient.
// A record is sealed to the room key when it is set. null ⇒ nothing is persisted (the privacy-safe default).
// ★ WHY THIS IS NOT SIMPLY TWO VARIABLES ANY MORE.
// These were module globals, and that was safe for as long as every caller was either a Lambda invocation (one
// request per process) or a single long-lived agent session (one room per process). Neither is true inside the
// enclave, which runs ONE Node process serving every request: a poll firing mid-turn ran its `finally`, cleared the
// key the in-flight turn was still using, and the turn's final seal silently produced nothing. The reply was
// discarded and the room simply never showed an answer.
//
// So the key now lives in per-request context when there IS one, and in the module scope when there is not:
//   - a SERVER wraps each request in `runWithKeyScope` → set/clear touches only that request's key
//   - the long-lived agent (agent.mjs) sets a key for its session with no scope → unchanged, as before
// No call site changes. The 18 existing callers of set/get keep working, and concurrency becomes safe by
// construction rather than by scheduling.
import { AsyncLocalStorage } from 'node:async_hooks'

const als = new AsyncLocalStorage()
let mk = null // module scope: the session case (no request context active)
const norm = (k) => (typeof k === 'string' && k.trim() ? k.trim() : null)
const scope = () => als.getStore()

export const setRoomKey = (k) => {
  const s = scope()
  if (s) s.mk = norm(k)
  else mk = norm(k)
}
export const getRoomKey = () => {
  const s = scope()
  return s ? s.mk : mk
}
export const hasRoomKey = () => !!getRoomKey()

// OLDER KEYS of a room re-keyed in place (docs/key-rotation-design.md § (b)): what was written before the rotation is
// sealed under its earlier keys, which the room's config (sealed under the current key) carries. They are tied to the
// key they were read with — `open` falls back to them only when it is asked to open with THAT key — and live only as
// long as the request's scope (module scope: the session case, where one room is served).
let older = new Map()
const olderMap = () => { const s = scope(); if (s) { if (!s.older) s.older = new Map(); return s.older } return older }
export const setOlderKeys = (forKey, keys) => {
  const k = norm(forKey); if (!k) return
  const m = olderMap(); const list = Array.isArray(keys) ? keys.map(norm).filter((x) => x && x !== k) : []
  if (list.length) m.set(k, list); else m.delete(k)
  if (m.size > 32) m.delete(m.keys().next().value) // module scope in a warm process: bounded
}
export const getOlderKeys = (forKey) => { const k = norm(forKey); return (k && olderMap().get(k)) || [] }

/** True if the sealing key is set — the gate for persisting at all. (Kept as `hasAnyKey` for its call sites; the
 *  room key is now the only key.) */
export const hasAnyKey = () => !!getRoomKey()

/**
 * Run `fn` with its own room-key scope. Anything a server handles concurrently should be wrapped in one, so one
 * request clearing its key cannot clear another's.
 *
 * The room key starts EMPTY in a new scope — deliberately. Inheriting it would mean a request that never presents a
 * key could seal with whatever the last one left behind, which is the failure this exists to prevent.
 */
export function runWithKeyScope(fn) {
  return als.run({ mk: null, older: new Map() }, fn)
}
