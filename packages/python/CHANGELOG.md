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
- **Read path:** verify on read (`unverified`/`stale`), per-read boundary wrapping, never drop.
- **LangGraph adapter:** `GuardedStore` with namespace isolation, a capability probe, and rollback through policy.
- **CLI:** `keys`, `review`, `incident`, `export`, `verify-ledger`, `doctor`, `redteam`.
- **Red-team pack v0** (T1a, T1d, T5, T6, T8, T10), `make bench` and `make demo`.
