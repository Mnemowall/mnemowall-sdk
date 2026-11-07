"""Read path (M1a-15/16): verify against the ledger, then wrap for the model. See §3.7."""

from mnemowall.read.verify import (
    BackendItem,
    MemoryRef,
    ReadCheck,
    ReadResult,
    read_memories,
    verify_item,
)
from mnemowall.read.wrap import (
    BOUNDARY_BITS,
    PREAMBLE,
    MemoryView,
    WrappedItem,
    WrappedRead,
    wrap_read,
)

__all__ = [
    "BOUNDARY_BITS",
    "PREAMBLE",
    "BackendItem",
    "MemoryRef",
    "MemoryView",
    "ReadCheck",
    "ReadResult",
    "WrappedItem",
    "WrappedRead",
    "read_memories",
    "verify_item",
    "wrap_read",
]
