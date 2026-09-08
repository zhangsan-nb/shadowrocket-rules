from __future__ import annotations

from _common import ROOT
from trusted_rules.commands import execute, report_command


if __name__ == "__main__":
    raise SystemExit(execute(report_command))

