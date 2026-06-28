from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


def partition(items: Sequence[T], batch_size: int) -> list[list[T]]:
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    return [list(items[i : i + batch_size]) for i in range(0, len(items), batch_size)]

