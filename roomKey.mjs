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
  return als.run({ mk: null }, fn)
}
