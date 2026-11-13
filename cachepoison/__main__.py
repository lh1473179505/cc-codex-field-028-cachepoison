"""CLI. inspect already works; process is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cachepoison.http import HTTPError, parse_message


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cachepoison")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="parse a request and a response")
    ins.add_argument("--request", required=True)
    ins.add_argument("--response", required=True)
    proc = sub.add_parser("process", help="compute a cache key and decide whether to store the response")
    proc.add_argument("--request", required=True)
    proc.add_argument("--response", required=True)
    proc.add_argument("--policy", required=True)
    proc.add_argument("--report", required=True)
    return p


def _summ(m):
    return {
        "kind": m.kind,
        "start": m.start,
        "headers": [{"name": n, "value": v} for n, v in m.headers],
        "body_len": len(m.body),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        req = parse_message(Path(args.request).read_bytes())
        resp = parse_message(Path(args.response).read_bytes())
    except (OSError, HTTPError) as exc:
        print(f"failed to parse messages: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps({"request": _summ(req), "response": _summ(resp)}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "process":
        try:
            policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"failed to load policy: {exc}", file=sys.stderr)
            return 2
        from cachepoison.engine import process

        try:
            report = process(req, resp, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
