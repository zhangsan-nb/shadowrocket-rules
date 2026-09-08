from __future__ import annotations

import argparse

from _common import ROOT
from trusted_rules.commands import execute
from trusted_rules.pipeline import build


def main() -> int:
    parser = argparse.ArgumentParser(description="构建并验证可信 RuleSet 候选")
    parser.add_argument("--ci", action="store_true", help="CI 模式（安全语义与本地模式相同）")
    args = parser.parse_args()
    return execute(lambda: build(ROOT, ci=args.ci))


if __name__ == "__main__":
    raise SystemExit(main())
