# Changelog

## 0.1.0 (unreleased; the founder tags the release)

First usable release (alpha).

- **Provenance:**
  - context API (`Guard`, sessions, `observe`, verified user turns);
  - forgery stripping of `_prov` and trust fields;
  - `@mnemowall.source`;
  - LangChain tool-output callback.
- **Signals:** S1, S2 (lexicon), S3 (sinks), S4 (obfuscation), S5, S7, S10.
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
- **Shared adapter contract suite:** the same tests run against LangGraph and Mem0.
- **Signed local policies:**
  - `mnemowall policy keygen/sign/verify` and `load_policy_file`;
  - a separate signing key, with only the public key pinned in the app;
  - a detached signature over the exact file bytes;
  - fails closed to the strict default;
  - a weaker-than-default policy waits 24 h;
  - YAML via `safe_load` only (`mnemowall[yaml]`).
- **Review delivery:** `deliver_reviewed()` on both adapters writes approved and promoted items into the memory store. It is idempotent, a newer write wins, and it stays within the adapter's tenant, scope and backend. An approved quarantined *delete* now commits a deletion, and can't be promoted.
- **CLI:** `keys`, `review`, `incident`, `export`, `verify-ledger`, `doctor`, `redteam`.
- **Red-team pack v0** (T1a, T1d, T5, T6, T8, T10), `make bench` and `make demo`.
