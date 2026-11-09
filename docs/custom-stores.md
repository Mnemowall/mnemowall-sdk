# Custom stores: the raw core API

Use `mnemowall.core.api.MemoryGuard` when your memory lives somewhere Mnemowall has no adapter for: your own Postgres table, pgvector, a vector database, or a key-value store. The guard makes every decision; your code does the storage.

```text
write:  guard_write(namespace, key, value) -> decision
        decision.outcome == "store"       -> persist decision.value at (decision.namespace, decision.key)
        decision.outcome == "delete"      -> remove (decision.namespace, decision.key)
        decision.outcome == "quarantined" -> persist nothing; a reviewer decides
read:   load rows from your store -> guard_read([StoredItem(...), ...]) -> views for the model
```

The rules that keep it safe:

1. **Persist exactly what the guard returns, where it says.** `decision.value` carries a signed reference. Change the value or move it to another key, namespace or user, and it reads back `unverified`.
2. **Never show stored rows to a model without `guard_read`.** It verifies each row against the ledger, wraps anything below the policy's trust threshold, logs the read for `mnemowall incident`, and registers what was read so later writes can't launder its trust.
3. **Query only the namespace the guard gives you** (`guard.location(...)`, the current session's own scope). `guard_read` drops rows from any other scope and counts them as `foreign_namespace_filtered`, a `doctor` error.
4. **If persisting fails, retry the same decision.** The ledger already holds the version; storing the same value twice is harmless.
5. **Call `deliver_reviewed(lookup)` at start-up or on a timer** to apply items a reviewer approved. Apply every decision it returns.

## Worked example: a dict-backed store

The SDK's tests execute this exact block and run the full adapter contract suite against it.

```python
from collections.abc import Iterable
from typing import Any

from mnemowall.core.api import MemoryGuard, ReadView, StoredItem, WriteDecision


class GuardedDictStore:
    """A key-value store in a dict, guarded by Mnemowall. Swap the dict for your database."""

    def __init__(self, guard: MemoryGuard) -> None:
        self.guard = guard
        self.rows: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}

    def _apply(self, decision: WriteDecision) -> None:
        where = (decision.namespace, decision.key)
        if decision.outcome == "store":
            self.rows[where] = decision.value  # exactly as returned, reference included
        elif decision.outcome == "delete":
            self.rows.pop(where, None)
        # "quarantined": store nothing

    def put(self, namespace: tuple[str, ...], key: str, value: dict[str, Any]) -> WriteDecision:
        decision = self.guard.guard_write(namespace, key, value)
        self._apply(decision)
        return decision

    def delete(self, namespace: tuple[str, ...], key: str) -> WriteDecision:
        decision = self.guard.guard_delete(namespace, key)
        self._apply(decision)
        return decision

    def _rows(self, namespace: tuple[str, ...]) -> Iterable[StoredItem]:
        where = self.guard.location(namespace)  # the current user's own scope only
        for (ns, key), value in self.rows.items():
            if ns == where:
                yield StoredItem(namespace=ns, key=key, value=value)

    def get(self, namespace: tuple[str, ...], key: str) -> ReadView | None:
        rows = [r for r in self._rows(namespace) if r.key == key]
        views = self.guard.guard_read(rows)
        return views[0] if views else None

    def search(self, namespace: tuple[str, ...], query: str) -> list[ReadView]:
        words = query.lower().split()
        hits = [r for r in self._rows(namespace) if any(w in str(r.value).lower() for w in words)]
        return self.guard.guard_read(hits, query=query)

    def rollback(self, memory_id: str, to_version: int) -> Any:
        result, decision = self.guard.rollback(memory_id, to_version)
        if decision is not None:
            self._apply(decision)
        return result

    def deliver_reviewed(self) -> dict[str, int]:
        decisions, counts = self.guard.deliver_reviewed(lambda ns, key: self.rows.get((ns, key)))
        for decision in decisions:
            self._apply(decision)
        return counts
```

Using it:

```python
from mnemowall.core.provenance import Guard

context = Guard()  # provenance: who is speaking, what the agent has read
guard = MemoryGuard(ledger=ledger, quarantine=quarantine, tenant_id="acme", store="notes")
store = GuardedDictStore(guard)

with context.session(tenant="acme", principal="alice", agent="assistant", session_id="s-1") as s:
    s.system_prompt()
    s.user_turn()
    store.put(("prefs",), "tea", {"text": "I prefer green tea."})
    view = store.get(("prefs",), "tea")
    prompt_text = view.text  # model-facing: wrapped when the policy says so
```

## What a `ReadView` holds

| Field | Meaning |
|---|---|
| `namespace`, `key` | Where the row lives, relative to the user's scope (what you passed to `guard_write`) |
| `value` | The stored value without Mnemowall's reference (and with any forged `_prov`/trust keys removed) |
| `text` | What to show the model: the value wrapped in per-read boundary markers when its trust is below the policy threshold, plain otherwise |
| `label` | `plain`, `data` or `unverified` |
| `trust`, `verified`, `stale` | Ledger verdict for this row |
| `memory_id`, `version_no` | For `mnemowall incident` and `rollback` |

## Limits

- **Weaker than an adapter in one way: you hold the pen.** An adapter guarantees every write goes through policy. With the raw API, code that writes to your store directly bypasses Mnemowall. Those rows read back `unverified`, but only if they pass through `guard_read`.
- **Namespaces and keys are opaque labels.** Non-empty strings of at most 256 characters with no control or format characters; namespace labels must not start with `_` (reserved). The guard stores your rows under `(scope prefix, "_raw", store, *your labels)`.
- **One store label per physical store.** `deliver_reviewed` uses it to find its own items when several stores share one ledger.
