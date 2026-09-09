from __future__ import annotations

import argparse
from pathlib import Path

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
        help="输入来源：live=实时 HTTPS（默认），snapshot=仅限带固定快照的取证复现；CI 强制 live",
    )
    parser.add_argument(
        "--scope-migration",
        type=Path,
        default=None,
        help="仅供一次性、人工批准的范围迁移工作流使用的契约文件",
    )
    args = parser.parse_args()
    return execute(
        lambda: build(
            ROOT,
            ci=args.ci,
            source_mode=args.source_mode,
            scope_migration_path=args.scope_migration,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
