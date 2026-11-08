"""Backend-agnostic adapter drivers for the shared contract suite (M1b-04, D44).

A backend joins the suite by implementing ``Driver``; ``test_conformance.py`` runs every shared
CT test once per driver. Adapter-specific behaviour stays in that adapter's own test file.
"""

from __future__ import annotations

import dataclasses
import itertools
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from langgraph.store.memory import InMemoryStore
from mem0_fakes import make_memory

from mnemowall.adapters._common import RollbackResult, scope_prefix
from mnemowall.adapters.langgraph import GuardedStore
from mnemowall.adapters.mem0 import GuardedMemory, derive_user_id
from mnemowall.core.provenance import Guard, ProvenanceSession
from mnemowall.core.trust import Source
from mnemowall.keys import EphemeralKeyProvider
from mnemowall.ledger import Ledger
from mnemowall.policy import load_policy
from mnemowall.quarantine import Quarantine
from mnemowall.signals.write import ScopeKind

PROVIDER = EphemeralKeyProvider()
PROVIDER.init()
TENANT = "tenant-a"


@dataclasses.dataclass(frozen=True)
class Read:
    raw: str  # the stored text
    model_text: str  # what the model is shown
    label: str
    trust: str
    verified: bool
    stale: bool
    memory_id: str
    version_no: int


class Driver(Protocol):
    name: str
    ledger: Ledger
    quarantine: Quarantine

    def put(self, text: str) -> str | None: ...
    def update(self, handle: str, text: str) -> None: ...
    def get(self, handle: str | None) -> Read | None: ...
    def search(self, query: str) -> list[Read]: ...
    def delete(self, handle: str) -> None: ...
    def rollback(self, memory_id: str, to_version: int) -> RollbackResult: ...
    def deliver(self) -> dict[str, int]: ...
    def inner_texts(self, principal: str = "alice") -> list[str]: ...
    def raw_plant(self, text: str) -> str: ...
    def raw_copy_to(self, handle: str, principal: str) -> str: ...
    def snapshot(self, handle: str) -> Any: ...
    def raw_restore(self, handle: str, snap: Any) -> None: ...
    def close(self) -> None: ...


@contextmanager
def session(
    kind: str = "trusted", *, principal: str = "alice", tenant: str = TENANT
) -> Iterator[ProvenanceSession]:
    g = Guard()
    with g.session(tenant=tenant, principal=principal, agent="agent", session_id="sess-1") as s:
        s.system_prompt()
        if kind == "verified":
            s.user_turn(verified=True, token=g.issue_confirmation("sess-1"))
        else:
            s.user_turn()
        if kind == "tainted":
            s.observe("an email", source=Source.EMAIL)
        yield s


def _open(tmp: Path) -> tuple[Ledger, Quarantine]:
    tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = Ledger.open(tmp / "ledger.db", PROVIDER, tenant_id=TENANT)
    quarantine = Quarantine.open(
        tmp / "quarantine", PROVIDER, ledger=ledger, policy=load_policy(), tenant_id=TENANT
    )
    return ledger, quarantine


NS = ("memories",)


class LangGraphDriver:
    name = "langgraph"

    def __init__(self, tmp: Path) -> None:
        self.ledger, self.quarantine = _open(tmp)
        self.inner = InMemoryStore()
        self.store = GuardedStore(
            self.inner, ledger=self.ledger, quarantine=self.quarantine, tenant_id=TENANT
        )
        self._keys = (f"k{i}" for i in itertools.count())

    def _ns(self, principal: str) -> tuple[str, ...]:
        return scope_prefix(TENANT, ScopeKind.USER, principal) + NS

    @staticmethod
    def _read(item: Any) -> Read | None:
        if item is None:
            return None
        labels = item.value["mnemowall"]
        return Read(
            raw=item.value["text"],
            model_text=labels["text"],
            label=labels["label"],
            trust=labels["trust"],
            verified=labels["verified"],
            stale=labels["stale"],
            memory_id=labels["memory_id"],
            version_no=labels["version_no"],
        )

    def put(self, text: str) -> str | None:
        key = next(self._keys)
        self.store.put(NS, key, {"text": text})
        return key

    def update(self, handle: str, text: str) -> None:
        self.store.put(NS, handle, {"text": text})

    def get(self, handle: str | None) -> Read | None:
        return None if handle is None else self._read(self.store.get(NS, handle))

    def search(self, query: str) -> list[Read]:
        return [r for r in (self._read(i) for i in self.store.search(NS, query=query)) if r]

    def delete(self, handle: str) -> None:
        self.store.delete(NS, handle)

    def rollback(self, memory_id: str, to_version: int) -> RollbackResult:
        return self.store.rollback(memory_id, to_version)

    def deliver(self) -> dict[str, int]:
        return self.store.deliver_reviewed()

    def inner_texts(self, principal: str = "alice") -> list[str]:
        return sorted(i.value["text"] for i in self.inner.search(self._ns(principal), limit=1000))

    def raw_plant(self, text: str) -> str:
        key = next(self._keys)
        self.inner.put(self._ns("alice"), key, {"text": text})
        return key

    def raw_copy_to(self, handle: str, principal: str) -> str:
        item = self.inner.get(self._ns("alice"), handle)
        assert item is not None
        self.inner.put(self._ns(principal), handle, dict(item.value))
        return handle

    def snapshot(self, handle: str) -> Any:
        item = self.inner.get(self._ns("alice"), handle)
        assert item is not None
        return dict(item.value)

    def raw_restore(self, handle: str, snap: Any) -> None:
        self.inner.put(self._ns("alice"), handle, snap)

    def close(self) -> None:
        self.quarantine.close()
        self.ledger.close()


class Mem0Driver:
    name = "mem0"

    def __init__(self, tmp: Path) -> None:
        self.ledger, self.quarantine = _open(tmp)
        self.inner = make_memory(tmp / "mem0")
        self.mem = GuardedMemory(
            self.inner, ledger=self.ledger, quarantine=self.quarantine, tenant_id=TENANT
        )

    @staticmethod
    def _uid(principal: str) -> str:
        return derive_user_id(TENANT, "user", principal)

    @staticmethod
    def _read(res: Any) -> Read | None:
        if res is None:
            return None
        labels = res["mnemowall"]
        return Read(
            raw=labels["raw"],
            model_text=res["memory"],
            label=labels["label"],
            trust=labels["trust"],
            verified=labels["verified"],
            stale=labels["stale"],
            memory_id=labels["memory_id"],
            version_no=labels["version_no"],
        )

    def put(self, text: str) -> str | None:
        (res,) = self.mem.add(text)["results"]
        return res["id"]  # type: ignore[no-any-return]

    def update(self, handle: str, text: str) -> None:
        self.mem.update(handle, text=text)

    def get(self, handle: str | None) -> Read | None:
        return None if handle is None else self._read(self.mem.get(handle))

    def search(self, query: str) -> list[Read]:
        return [r for r in (self._read(i) for i in self.mem.search(query)["results"]) if r]

    def delete(self, handle: str) -> None:
        self.mem.delete(handle)

    def rollback(self, memory_id: str, to_version: int) -> RollbackResult:
        return self.mem.rollback(memory_id, to_version)

    def deliver(self) -> dict[str, int]:
        return self.mem.deliver_reviewed()

    def inner_texts(self, principal: str = "alice") -> list[str]:
        found = self.inner.get_all(filters={"user_id": self._uid(principal)}, top_k=1000)
        return sorted(r["memory"] for r in found["results"])

    def raw_plant(self, text: str) -> str:
        out = self.inner.add(text, user_id=self._uid("alice"), infer=False)
        return out["results"][0]["id"]  # type: ignore[no-any-return]

    def raw_copy_to(self, handle: str, principal: str) -> str:
        item = self.inner.get(handle)
        out = self.inner.add(
            item["memory"], user_id=self._uid(principal), metadata=item["metadata"], infer=False
        )
        return out["results"][0]["id"]  # type: ignore[no-any-return]

    def snapshot(self, handle: str) -> Any:
        item = self.inner.get(handle)
        return {"text": item["memory"], "metadata": dict(item["metadata"])}

    def raw_restore(self, handle: str, snap: Any) -> None:
        self.inner.update(handle, text=snap["text"], metadata=snap["metadata"])

    def close(self) -> None:
        self.quarantine.close()
        self.ledger.close()


class Mem0InferDriver(Mem0Driver):
    """Mem0 infer mode (beta, D40): writes go through Mem0's own extraction; the scripted model
    "extracts" exactly the text, so the shared expectations apply after reconciliation."""

    name = "mem0-infer"

    def __init__(self, tmp: Path) -> None:
        self.ledger, self.quarantine = _open(tmp)
        self.inner = make_memory(tmp / "mem0")
        self.mem = GuardedMemory(
            self.inner,
            ledger=self.ledger,
            quarantine=self.quarantine,
            tenant_id=TENANT,
            mode="infer",
        )

    def put(self, text: str) -> str | None:
        self.inner.llm.script.append([text])
        (res,) = self.mem.add(f"message: {text}", infer=True)["results"]
        return res["id"]  # type: ignore[no-any-return]


DRIVERS = {"langgraph": LangGraphDriver, "mem0": Mem0Driver, "mem0-infer": Mem0InferDriver}
