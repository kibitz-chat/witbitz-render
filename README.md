# Witbitz — the render

**This is the code that touches your plaintext.** In a Witbitz Space, messages are sealed at rest and the
client is thin, so there is exactly one place data is ever decrypted: a transient, server-side *render*,
invoked on an AI turn and on every changed read. That surface is small — a few hundred lines — and this
repository is it, published to be **read**.

> "Verify the code, not the operator" only means something when the code can be *read*, not just re-hashed.
> A pinned build proves the bytes you run are the bytes certified; it says nothing about whether those bytes
> are trustworthy. This is the other half.

## The surface

| File | Lines | What it does |
|---|---:|---|
| [`envelope.mjs`](./envelope.mjs) | 287 | The seal/open primitive. A fresh per-write content key, wrapped **per recipient** — `room` symmetrically under `HKDF(mk)`, others via ECDH `sealTo`/`openBox`. There is **no operator/admin recipient** in production. |
| [`asyncTurn.mjs`](./asyncTurn.mjs) | 228 | One decrypt-once turn: open the sealed ledger with `mk`, append the incoming message, ask the model, append the reply, re-seal, store — then drop `mk`. |
| [`spacePoll.mjs`](./spacePoll.mjs) | 79 | The read side. The sealed blob never leaves the server; an unchanged read never decrypts (the etag is a hash of the *ciphertext*); a changed read returns only the **new** entries as plaintext, and needs `mk` to do it. |
| [`sessionStore.mjs`](./sessionStore.mjs) | 243 | Session memory, sealed with `mk` — platform-blind, and fail-safe (no `mk` ⇒ nothing is written or read). |

**594 lines** for the seal / turn / read core; **837** including session memory.

## How to trust that this is what actually runs

These files are a **readable mirror**. The hash-verified canonical is the full, reproducible bundle:

- **`source.tar.gz`** — <https://witbitz-spaces.pages.dev/source.tar.gz> — the exact render source, which
  rebuilds **byte-for-byte** to the running Lambda's `CodeSha256`.
- **`cert.json`** — <https://witbitz-spaces.pages.dev/cert.json> — a signed certificate binding the git
  commit, that `CodeSha256`, and the egress allowlist to ground truth.
- The step-by-step checks live in **verify.md**: <https://docs.witbitz.chat/docs/verify.md> (Tests 6–7).

So: read the logic here; confirm the deployed bytes match, yourself, via `source.tar.gz`.

## Honest scope

This is the *plaintext surface*, not a runnable app — these modules import orchestration code (the model
adapter, config, storage) that lives in the full bundle. And reading the code proves what the code *does*,
not that the running **process** can't be observed during that transient decrypt instant — that is the
attested / TEE tier, the one rung still ahead. Everything up to *"the code is exactly this, and it's
readable"* is here.

## License

[Apache-2.0](./LICENSE). See [NOTICE](./NOTICE).

---

Part of [Witbitz](https://witbitz.chat) · docs at <https://docs.witbitz.chat>
