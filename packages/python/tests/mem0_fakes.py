"""Keyless, deterministic Mem0 test fixtures (D43): in-process Qdrant, a hashing embedder, a
scripted LLM. They are injected by replacing ``embedding_model``/``llm`` on a built ``Memory``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mem0 import AsyncMemory, Memory
from mem0.configs.base import MemoryConfig
from qdrant_client import QdrantClient

DIMS = 64
_WORD = re.compile(r"[a-z0-9]+")


class HashEmbedder:
    """Bag of hashed words, L2-normalised: similar texts get similar vectors."""

    def __init__(self) -> None:
        self.calls = 0

    def embed(self, text: Any, memory_action: str | None = None) -> list[float]:
        self.calls += 1
        vec = [0.0] * DIMS
        vec[0] = 0.01
        for word in _WORD.findall(str(text).lower()):
            h = hashlib.sha256(word.encode()).digest()
            vec[h[0] % DIMS] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec]

    def embed_batch(self, texts: list[str], memory_action: str | None = None) -> list[list[float]]:
        return [self.embed(t, memory_action) for t in texts]


class ScriptedLLM:
    """Returns the next scripted extraction; records that it was called."""

    def __init__(self) -> None:
        self.script: list[list[str]] = []
        self.calls = 0
        self.hook: Callable[[], None] | None = None

    def generate_response(self, messages: Any = None, **_: Any) -> str:
        self.calls += 1
        if self.hook is not None:
            self.hook()
        facts = self.script.pop(0) if self.script else []
        return json.dumps({"memory": [{"text": f} for f in facts]})


def _config(tmp: Path) -> MemoryConfig:
    tmp.mkdir(parents=True, exist_ok=True)
    return MemoryConfig(
        vector_store={
            "provider": "qdrant",
            "config": {
                "client": QdrantClient(":memory:"),
                "embedding_model_dims": DIMS,
                "collection_name": "contract",
            },
        },
        embedder={
            "provider": "openai",
            "config": {"api_key": "sk-test-unused", "embedding_dims": DIMS},
        },
        llm={"provider": "openai", "config": {"api_key": "sk-test-unused"}},
        history_db_path=str(tmp / "history.db"),
    )


class EventMemory(Memory):  # type: ignore[misc]  # mem0 is untyped
    """A Mem0 whose infer ``add`` runs a scripted action instead: it simulates versions that emit
    ``UPDATE``/``DELETE`` events, or a store that writes and then fails (V2)."""

    action: Callable[[Memory], Any] | None = None
    active = 0
    max_active = 0

    def add(
        self,
        messages: Any,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        run_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        infer: bool = True,
        memory_type: str | None = None,
        prompt: str | None = None,
    ) -> Any:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if infer and self.action is not None:
                return self.action(self)
            return super().add(
                messages,
                user_id=user_id,
                agent_id=agent_id,
                run_id=run_id,
                metadata=metadata,
                infer=infer,
                memory_type=memory_type,
                prompt=prompt,
            )
        finally:
            self.active -= 1


def make_memory(tmp: Path, cls: type[Memory] = Memory) -> Memory:
    m = cls(_config(tmp))
    m.embedding_model = HashEmbedder()
    m.llm = ScriptedLLM()
    return m


def make_async_memory(tmp: Path) -> AsyncMemory:
    m = AsyncMemory(_config(tmp))
    m.embedding_model = HashEmbedder()
    m.llm = ScriptedLLM()
    return m


def raw_texts(m: Memory, user_id: str) -> list[str]:
    return sorted(
        r["memory"] for r in m.get_all(filters={"user_id": user_id}, top_k=1000)["results"]
    )
