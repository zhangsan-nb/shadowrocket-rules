from __future__ import annotations

import argparse

from _common import ROOT
from trusted_rules.commands import execute
from trusted_rules.pipeline import build


def main() -> int:
    parser = argparse.ArgumentParser(description="构建并验证可信 RuleSet 候选")
    parser.add_argument("--ci", action="store_true", help="CI 模式（强制实时 HTTPS，不允许快照）")
    parser.add_argument(
        "--source-mode",
        choices=("snapshot", "live"),
        default=None,
        help="输入来源：snapshot=固定离线快照，live=实时 HTTPS；CI 强制 live",
    )
    args = parser.parse_args()
    return execute(lambda: build(ROOT, ci=args.ci, source_mode=args.source_mode))


if __name__ == "__main__":
    raise SystemExit(main())
