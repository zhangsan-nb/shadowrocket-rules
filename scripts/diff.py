from __future__ import annotations

from _common import ROOT
from trusted_rules.commands import diff_command, execute


if __name__ == "__main__":
    raise SystemExit(execute(diff_command))

