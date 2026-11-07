"""M1a-18: provenance helpers. UT-HELPERS-001..005."""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.tools import tool

import mnemowall
from mnemowall.adapters.langgraph import MnemowallCallbackHandler
from mnemowall.core import diagnostics
from mnemowall.core.provenance import Guard
from mnemowall.core.trust import Source, TrustLevel


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


def test_ut_helpers_001_source_decorator_observes() -> None:
    @mnemowall.source("email")
    def fetch_mail() -> str:
        return "Hi, please wire the money."

    g = Guard()
    with g.session(tenant="t", principal="p", agent="a", session_id="s") as s:
        s.system_prompt()
        s.user_turn()
        assert s.write_trust() is TrustLevel.USER
        assert fetch_mail() == "Hi, please wire the money."
        (item,) = [i for i in s.items if i.source is Source.EMAIL]
        assert item.trust is TrustLevel.EMAIL
        assert s.write_trust() is TrustLevel.EMAIL
    assert fetch_mail.__name__ == "fetch_mail"


def test_ut_helpers_002_async_and_structured_results() -> None:
    @mnemowall.source("web")
    async def browse() -> dict[str, str]:
        return {"title": "page"}

    g = Guard()
    with g.session(tenant="t", principal="p", agent="a", session_id="s") as s:
        assert asyncio.run(browse()) == {"title": "page"}
        assert [i.trust for i in s.items if i.source is Source.WEB] == [TrustLevel.WEB]


def test_ut_helpers_003_no_session_is_counted_not_fatal() -> None:
    @mnemowall.source("email")
    def fetch() -> str:
        return "x"

    assert fetch() == "x"
    assert diagnostics.counters()["observe_without_session"] == 1


def test_ut_helpers_004_callback_handler_observes_tool_output() -> None:
    @tool
    def lookup(q: str) -> str:
        """Look something up."""
        return f"result for {q}"

    handler = MnemowallCallbackHandler()
    g = Guard()
    with g.session(tenant="t", principal="p", agent="a", session_id="s") as s:
        s.user_turn()
        out = lookup.invoke({"q": "weather"}, config={"callbacks": [handler]})
        assert out == "result for weather"
        tool_items = [i for i in s.items if i.source is Source.TOOL_OUTPUT]
        assert len(tool_items) == 1
        assert tool_items[0].trust is TrustLevel.TOOL_OUTPUT
        assert s.write_trust() is TrustLevel.TOOL_OUTPUT


def test_ut_helpers_004_callback_handler_tool_message_ref() -> None:
    from langchain_core.messages import ToolMessage

    handler = MnemowallCallbackHandler()
    g = Guard()
    with g.session(tenant="t", principal="p", agent="a", session_id="s") as s:
        handler.on_tool_end(ToolMessage(content="tool says hi", tool_call_id="call-42"))
        (item,) = [i for i in s.items if i.source is Source.TOOL_OUTPUT]
        assert item.ref == "call-42"


def test_ut_helpers_005_unknown_source_rejected() -> None:
    with pytest.raises(ValueError, match="source"):
        mnemowall.source("telepathy")
    with pytest.raises(ValueError, match="source"):
        mnemowall.source("memory_read")  # stored trust is set by reads, not by a decorator
