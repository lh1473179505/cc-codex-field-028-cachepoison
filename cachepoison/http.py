"""Parse a raw HTTP/1.1 request or response. Cache admission is not implemented here."""

from __future__ import annotations

from dataclasses import dataclass, field


class HTTPError(Exception):
    pass


@dataclass
class Message:
    kind: str
    start: str
    method: str | None = None
    target: str | None = None
    version: str | None = None
    status: int | None = None
    reason: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    raw: bytes = b""

    def header(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for n, v in self.headers if n.lower() == lname]


def parse_message(data: bytes) -> Message:
    if b"\r\n\r\n" not in data:
        raise HTTPError("truncated_headers")
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise HTTPError("bad_start")
    start = lines[0].decode("latin1")
    parts = start.split(" ", 2)
    method = target = version = None
    status = reason = None
    kind = "request"
    if parts[0].startswith("HTTP/"):
        kind = "response"
        version = parts[0]
        try:
            status = int(parts[1])
        except (IndexError, ValueError) as exc:
            raise HTTPError("bad_status") from exc
        reason = parts[2] if len(parts) > 2 else ""
    else:
        if len(parts) < 3:
            raise HTTPError("bad_request_line")
        method, target, version = parts[0], parts[1], parts[2]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if b":" not in line:
            raise HTTPError("bad_header")
        n, v = line.split(b":", 1)
        headers.append((n.decode("latin1"), v.decode("latin1").strip()))
    return Message(
        kind=kind, start=start, method=method, target=target, version=version,
        status=status, reason=reason, headers=headers, body=body, raw=data,
    )
