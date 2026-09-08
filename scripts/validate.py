from __future__ import annotations

import argparse
from pathlib import Path

from _common import ROOT
from trusted_rules.commands import execute, validate_command


def main() -> int:
    parser = argparse.ArgumentParser(description="校验已生成候选及 manifest")
    parser.add_argument("--candidate", type=Path, default=ROOT / "candidate")
    args = parser.parse_args()
    return execute(lambda: validate_command(args.candidate))


if __name__ == "__main__":
    raise SystemExit(main())

