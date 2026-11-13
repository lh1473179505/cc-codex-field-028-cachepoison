"""Cache key + store admission. See docs/process-rules.md."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from cachepoison.http import Message

_OVERRIDE_HEADERS = ("x-http-method-override", "x-method-override")
_LOWERCASED_KEY_VALUES = {"accept", "accept-language"}
_JS_TYPES = {"application/javascript", "text/javascript", "application/x-javascript"}


def _first_header(message: Message, name: str) -> str | None:
    values = message.header(name)
    return values[0] if values else None


def _canonical_host(host: str, scheme: str | None) -> str:
    host = host.strip().lower()
    if scheme == "http" and host.endswith(":80"):
        host = host[: -len(":80")]
    elif scheme == "https" and host.endswith(":443"):
        host = host[: -len(":443")]
    return host


def _normalize_target(target: str, policy: dict, reasons: list[str]) -> tuple[str, str]:
    """Return (path, scheme). Path keeps a canonical sorted query."""
    scheme: str | None = None
    if target.startswith("http://") or target.startswith("https://"):
        parts = urlsplit(target)
        scheme = parts.scheme.lower()
        path = parts.path or "/"
        query = parts.query
    else:
        path, _, query = target.partition("?")
        if not path:
            path = "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/") or "/"
    unkeyed = {k.lower() for k in policy.get("unkeyed_query", [])}
    forbidden = {k.lower() for k in policy.get("forbidden_query", [])}
    pairs = parse_qsl(query, keep_blank_values=True)
    kept = []
    for name, value in pairs:
        if name.lower() in forbidden:
            if "dangerous_query" not in reasons:
                reasons.append("dangerous_query")
            continue
        if name.lower() in unkeyed:
            continue
        kept.append((name, value))
    kept.sort(key=lambda item: (item[0], item[1]))
    if kept:
        path = path + "?" + urlencode(kept)
    return path, scheme


def _compute_key(
    request: Message, policy: dict, reasons: list[str], notes: list[str]
) -> str | None:
    method = (request.method or "").upper()
    override = None
    for name in _OVERRIDE_HEADERS:
        override = _first_header(request, name)
        if override is not None:
            break
    if override is not None:
        if policy.get("ignore_method_override", False):
            if method in [m.upper() for m in policy.get("cacheable_methods", [])]:
                reasons.append("method_override")
                notes.append(
                    "method override header on a cacheable " + method + " must not be stored"
                )
        else:
            method = override.strip().upper()

    path, scheme = _normalize_target(request.target or "/", policy, reasons)
    if scheme is None:
        proto = _first_header(request, "x-forwarded-proto")
        if proto:
            scheme = proto.strip().lower()

    host = _first_header(request, "host")
    if host is None:
        reasons.append("missing_host")
        notes.append("request has no Host header; cannot compute a cache key")
        return None
    host = _canonical_host(host, scheme)

    xfh = _first_header(request, "x-forwarded-host")
    keyed = {h.lower() for h in policy.get("keyed_headers", [])}
    if xfh is not None and "x-forwarded-host" not in keyed:
        if _canonical_host(xfh, scheme) != host:
            reasons.append("unkeyed_host")
            notes.append(
                "X-Forwarded-Host differs from Host but is not part of the cache key"
            )

    must_key = {h.lower() for h in policy.get("must_key_if_present", [])}
    present = {n.lower() for n, _ in request.headers}
    for name in sorted(must_key & present - keyed):
        if "unkeyed_header" not in reasons:
            reasons.append("unkeyed_header")
        notes.append("header not in keyed_headers: " + name)

    lines = [method, path, "host=" + host]
    for name in sorted(keyed):
        value = _first_header(request, name)
        if value is None:
            continue
        value = value.strip()
        if name in _LOWERCASED_KEY_VALUES:
            value = value.lower()
        lines.append(name + ":" + value)
    return "\n".join(lines) + "\n"


def _content_type(response: Message) -> str:
    value = _first_header(response, "content-type") or ""
    return value.split(";", 1)[0].strip().lower()


def _store_reasons(
    request: Message, response: Message, policy: dict, notes: list[str]
) -> list[str]:
    reasons: list[str] = []
    method = (request.method or "").upper()
    cacheable_methods = [m.upper() for m in policy.get("cacheable_methods", [])]
    if method not in cacheable_methods:
        reasons.append("method_not_cacheable")
    if method == "GET" and request.body:
        reasons.append("fat_get")
        notes.append("GET with a non-empty body must not be stored")

    if response.status not in policy.get("cacheable_status", []):
        reasons.append("status_not_cacheable")

    for value in response.header("cache-control"):
        tokens = {t.strip().lower() for t in value.split(",")}
        if tokens & {"no-store", "private"}:
            reasons.append("cache_control")
            break

    set_cookies = response.header("set-cookie")
    if set_cookies and not policy.get("store_set_cookie", False):
        reasons.append("set_cookie")

    splitting = any(
        "\r" in value or "\n" in value or "\r" in name or "\n" in name
        for name, value in response.headers
    )
    if policy.get("forbid_crlf_in_body", False) and b"\r" in response.body:
        splitting = True
    if splitting:
        reasons.append("response_splitting")

    if policy.get("enforce_type_by_ext", False):
        target = (request.target or "").split("?", 1)[0].lower()
        ctype = _content_type(response)
        if target.endswith(".js") and ctype not in _JS_TYPES:
            reasons.append("type_mismatch")
        elif target.endswith(".css") and ctype != "text/css":
            reasons.append("type_mismatch")
    if _content_type(response) in {
        t.lower() for t in policy.get("unstoreable_types", [])
    }:
        if "type_mismatch" not in reasons:
            reasons.append("type_mismatch")

    proto = _first_header(request, "x-forwarded-proto")
    if proto and proto.strip().lower() == "http":
        for cookie in set_cookies:
            attrs = {a.strip().lower() for a in cookie.split(";")}
            if "secure" in attrs:
                reasons.append("proto_cookie")
                notes.append("Secure cookie set over forwarded http proto")
                break
    return reasons


def process(request: Message, response: Message, policy: dict) -> dict[str, Any]:
    reasons: list[str] = []
    notes: list[str] = []
    key = _compute_key(request, policy, reasons, notes)
    reasons.extend(_store_reasons(request, response, policy, notes))

    seen = set()
    reason_codes = [r for r in reasons if not (r in seen or seen.add(r))]
    decision = "deny" if reason_codes else "allow"

    stored = None
    if decision == "allow":
        hop_by_hop = {h.lower() for h in policy.get("hop_by_hop", [])}
        stored = {
            "key": key,
            "status": response.status,
            "headers": [
                {"name": name, "value": value}
                for name, value in response.headers
                if name.lower() not in hop_by_hop
            ],
            "body_hex": response.body.hex(),
        }
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "key": key,
        "stored": stored,
        "notes": notes,
    }
