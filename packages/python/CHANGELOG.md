# Changelog

## 0.1.0 (unreleased; the founder tags the release)

First usable release (alpha).

- **Provenance:**
  - context API (`Guard`, sessions, `observe`, verified user turns);
  - forgery stripping of `_prov` and trust fields;
  - `@mnemowall.source`;
  - LangChain tool-output callback.
- **Signals:** S1, S2 (lexicon), S3 (sinks), S4 (obfuscation), S5, S7, S10. S3 covers the full §3.5 list: URLs, emails, image beacons, IBANs, phone numbers, checksummed crypto addresses (Bech32/Bech32m, Base58Check, `0x`), credential paths and shell download-and-run. Sinks are also matched after NFKC folding and refanging (`hxxps://`, `[.]`, `[at]`). S2 also classifies a de-spaced, de-leeted copy (`S2.deobfuscated`). S4 flags short base64/hex blobs that decode to readable text (`S4.encoded_text`).
- **Write policy:**
  - invariants I1–I9 with a built-in strict default;
  - `enforce` and `shadow` modes;
  - stricter-only local overrides.
- **Ledger:**
  - Ed25519 version signatures over JCS;
  - an encrypted SQLite ledger with per-memory and global hash chains;
  - read log, retention and purge.
- **Quarantine:** a separate encrypted store, an encrypted pending buffer, and review with a 24 h promotion delay.
- **Read path:**
  - verify on read (`unverified`/`stale`), per-read boundary wrapping, never drop;
  - location binding: a signed item copied to another key, namespace or principal reads `unverified` (`location_mismatch`).
- **LangGraph adapter:** `GuardedStore` with namespace isolation, a capability probe, and rollback through policy.
- **Mem0 OSS adapter** (`mnemowall[mem0]`, strict mode):
  - `GuardedMemory`/`GuardedAsyncMemory` with a derived `user_id`;
  - ownership checks on id-based calls;
  - plain-equality filters;
  - wrapped `memory` on read;
  - rollback through policy.
- **Mem0 infer mode (beta, detective; `mode="infer"`):**
  - Mem0 extracts and stores; Mnemowall diffs the scope under a per-user lock, signs what policy commits, removes and quarantines the rest, and restores protected memories Mem0 changed or deleted;
  - trust is capped at what Mem0's model could have seen: memories in scope and the last 10 infer calls' messages (signed `infer` ledger events);
  - `provenance.trust_cap()` (lowers write trust only);
  - `doctor`: `infer_removed`, `infer_restored`, and `mem0_logs_content` when the `mem0` logger is below CRITICAL.
- **Shared adapter contract suite:** the same tests run against LangGraph, Mem0 strict and Mem0 infer mode.
- **Signed local policies:**
  - `mnemowall policy keygen/sign/verify` and `load_policy_file`;
  - a separate signing key, with only the public key pinned in the app;
  - a detached signature over the exact file bytes;
  - fails closed to the strict default;
  - a weaker-than-default policy waits 24 h;
  - YAML via `safe_load` only (`mnemowall[yaml]`).
- **Red-team pack, corpus v1:** eight classes (T1a, T1b, T1c, T1d, T5, T6, T8, T10), 500 attacks each, plus 5,600 benign samples in ten categories (most of them trusted-user hard negatives). Generated reproducibly from encoded, self-written templates (pinned SHA-256); rates reported with Wilson 95% intervals. `mnemowall redteam --benign` reports false positives per category; `--sample N` runs a quick subset.
- **Benchmark report v0:** `make bench` (`python -m mnemowall.bench_report`) writes one JSON and one Markdown report with red-team catch rates (Wilson 95%, protected and unprotected), benign false positives per category, and hot-path latency per stage against the §3.8 budgets, plus package pins, corpus seed and SHA-256, hardware and load.
- **Review delivery:** `deliver_reviewed()` on both adapters writes approved and promoted items into the memory store. It is idempotent, a newer write wins, and it stays within the adapter's tenant, scope and backend. An approved quarantined *delete* now commits a deletion, and can't be promoted.
- **CLI:** `keys`, `review`, `incident`, `export`, `verify-ledger`, `doctor`, `redteam`.
- **Red-team pack v0** (T1a, T1d, T5, T6, T8, T10), `make bench` and `make demo`.
