from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from _common import ROOT
from trusted_rules.commands import execute
from trusted_rules.seal import seal_candidate, verify_and_extract


def main() -> int:
    parser = argparse.ArgumentParser(description="密封或核验候选传输制品")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--candidate", type=Path, default=ROOT / "candidate")
    create.add_argument("--archive", type=Path, default=ROOT / "dist" / "candidate.zip")
    create.add_argument("--digest", type=Path, default=ROOT / "dist" / "candidate.zip.sha256")
    verify = sub.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--digest", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        return execute(lambda: {"transport_sha256": seal_candidate(args.candidate, args.archive, args.digest)})
    if args.output.exists():
        shutil.rmtree(args.output)
    return execute(lambda: verify_and_extract(args.archive, args.digest, args.output) or {"output": str(args.output)})


if __name__ == "__main__":
    raise SystemExit(main())

