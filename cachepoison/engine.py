"""Cache key + store admission. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from cachepoison.http import Message


def process(request: Message, response: Message, policy: dict) -> dict[str, Any]:
    raise NotImplementedError("process is not implemented in this snapshot")
