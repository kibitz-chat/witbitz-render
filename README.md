# Witbitz — the render

**This is the code that touches your plaintext — and it runs inside an attested enclave.** Every room is sealed under
its own room key (`mk`), which lives with the members, in the room link. To run an AI turn the room has to be opened;
on Witbitz's confidential tier that happens only inside an always-on **AWS Nitro enclave**, whose exact build is
published, reproducible, audited and pinned. Not the server relaying the request, and not us. This repository is that
code, published to be **read**.

> "Verify the code, not the operator" only means something when the code can be *read*, not just re-hashed. The
> enclave's measurements prove the bytes that run are the bytes published; this is where you read what they do.

## The confidential tier — the enclave

- **Always on.** One Nitro enclave serves every confidential room; there is no cold start and no fallback to a
  non-enclave path.
- **Sealed to the measured build.** The member's device seals `mk` to the enclave's attested key, so only the build
  whose measurement is published can open the room. The relaying server only ever carries opaque bytes.
- **Reproducible and pinned.** The payload (this code and its dependencies) is built deterministically and measured
  into the enclave's PCRs; its network egress list is measured too. The published claim names those values —
  [`enclave-claim.json`](https://witbitz-spaces.pages.dev/enclave-claim.json),
  [`enclave-policy.json`](https://witbitz-spaces.pages.dev/enclave-policy.json) — and a client refuses an enclave
  that does not match.
- **Audited before it ships.** No build can be pinned without a passing audit verdict, and every verdict is published
  in a hash-chained log: [`/audit/turn-enclave.jsonl`](https://witbitz-spaces.pages.dev/audit/turn-enclave.jsonl).
- **Every reply is certified.** Each confidential reply carries a turn certificate signed inside the enclave (an RFC 9711
  EAT), naming the build that produced it; the app verifies it against AWS's Nitro root.

## The surface

| File | Lines | What it does |
|---|---:|---|
| [`envelope.mjs`](./envelope.mjs) | 263 | The seal/open primitive: a fresh content key per write, wrapped for the room under `HKDF(mk)` (AES-256-GCM); `sealTo`/`openBox` for a single recipient's public key. **There is no operator or admin recipient.** |
| [`roomKey.mjs`](./roomKey.mjs) | 50 | Where `mk` lives while a request runs — per-request memory, cleared after it. |
| [`spaceLedgerV3.mjs`](./spaceLedgerV3.mjs) | 111 | The ledger format: each entry is its own sealed box; every new box is bound to its room and position (the AES-GCM AAD), so it cannot be moved, duplicated or replayed undetected. |
| [`asyncTurn.mjs`](./asyncTurn.mjs) | 825 | One AI turn: open the ledger with `mk`, add the incoming message, decide whether the assistant should reply, ask the model, append the reply, drop `mk`. |
| [`spacePoll.mjs`](./spacePoll.mjs) | 187 | Reads. Content-blind (`pollsealed`): sealed boxes after the reader's position, no `mk`. Or opened (`poll`): the reader sends `mk` for the new entries. An unchanged read touches neither. |
| [`sessionStore.mjs`](./sessionStore.mjs) | 1,040 | Storage: the ledger and the room's sealed side documents. No `mk`, no write. Appends are compare-and-set, so concurrent writers never lose each other's entries. |
| [`ledgerSegments.mjs`](./ledgerSegments.mjs) | 166 | The ledger stored in segments, so an append rewrites one small object, not the history. Layout only — never a key or a byte of plaintext. |

**1,436 lines** for the seal / turn / read core; **2,642** with storage.

## The standard tier

Each app chooses a room's tier when it creates it. A room created on the standard tier runs the same code in the
server's request handler instead of the enclave: the device sends `mk` with a request, the server holds it in memory
for that request only, and stores nothing but ciphertext. Reading the code tells you what it does; it cannot prove the
process is not observed while a room is open — which is exactly what the confidential tier is for.

## How to check what runs

- **Confidential tier:** the enclave claim and policy above, the audit log, and each reply's turn certificate.
- **Standard tier:** [`source.tar.gz`](https://witbitz-spaces.pages.dev/source.tar.gz) is the exact deployed server
  source and rebuilds byte-for-byte to the running Lambda's `CodeSha256`; [`cert.json`](https://witbitz-spaces.pages.dev/cert.json)
  binds the git commit, that hash and the page's network allow-list.
- The checks, step by step: <https://docs.witbitz.chat/docs/verify.md> · the model: <https://docs.witbitz.chat/docs/trust-model.md>

These files are a readable mirror of the repository at the commit named in [`SOURCE`](./SOURCE). They are the
plaintext surface, not a runnable app: they import orchestration (model adapters, room configuration, the request
handler) that ships in the full bundle and in the enclave payload.
