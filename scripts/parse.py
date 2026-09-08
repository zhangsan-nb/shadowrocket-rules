from __future__ import annotations

import argparse
from pathlib import Path

from _common import ROOT
from trusted_rules.commands import execute
from trusted_rules.config import load_lines
from trusted_rules.parser import parse_rules


def main() -> int:
    parser = argparse.ArgumentParser(description="严格解析单个 RuleSet")
    parser.add_argument("path", type=Path)
    parser.add_argument("--category", choices=("direct", "reject", "proxy"), required=True)
    args = parser.parse_args()
    return execute(
        lambda: {
            "rules": len(
                parse_rules(
                    args.path.read_text(encoding="utf-8"),
                    category=args.category,
                    source=args.path.name,
                    allow_types=set(load_lines(ROOT / "config" / "allow_rule_types.txt")),
                )
            )
        }
    )


if __name__ == "__main__":
    raise SystemExit(main())

