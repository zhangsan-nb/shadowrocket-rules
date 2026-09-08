from __future__ import annotations

import argparse
from pathlib import Path

from _common import ROOT
from trusted_rules.commands import execute
from trusted_rules.release import publish_candidate, rollback_release


def main() -> int:
    parser = argparse.ArgumentParser(description="连续历史、仅快进的 release 发布器")
    sub = parser.add_subparsers(dest="command", required=True)
    publish = sub.add_parser("publish")
    publish.add_argument("--candidate", type=Path, default=ROOT / "candidate")
    publish.add_argument("--local-only", action="store_true")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("target")
    rollback.add_argument("--local-only", action="store_true")
    args = parser.parse_args()
    if args.command == "publish":
        return execute(lambda: {"release_commit": publish_candidate(ROOT, args.candidate, local_only=args.local_only)})
    return execute(lambda: {"release_commit": rollback_release(ROOT, args.target, local_only=args.local_only)})


if __name__ == "__main__":
    raise SystemExit(main())

