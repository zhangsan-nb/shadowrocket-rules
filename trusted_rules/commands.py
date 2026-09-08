from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

from .artifacts import canonical_json, verify_manifest
from .config import load_json_yaml, load_lines
from .errors import ExitCode, TrustedRulesError
from .fetcher import fetch_source
from .pipeline import build, repository_root


def execute(action: Callable[[], object]) -> int:
    try:
        result = action()
        if result is not None:
            print(json.dumps({"status": "PASS", "result": result}, ensure_ascii=False, sort_keys=True))
        return int(ExitCode.PASS)
    except TrustedRulesError as exc:
        print(
            json.dumps(
                {"status": "FAIL", "error": exc.key, "message": str(exc), "exit_code": int(exc.code)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(exc.code)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "FAIL", "error": "build.unhandled", "message": str(exc), "exit_code": 1},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(ExitCode.BUILD_ERROR)


def fetch_command(repo: Path | None = None) -> dict[str, object]:
    repo = (repo or repository_root()).resolve()
    sources = load_json_yaml(repo / "config" / "sources.yml")
    policy = load_json_yaml(repo / "config" / "policy.yml")
    destination = repo / "work" / "fetched"
    destination.mkdir(parents=True, exist_ok=True)
    metadata = []
    for name, source in sources.get("sources", {}).items():
        if not source.get("enabled", False):
            continue
        text, item = fetch_source(name, source, policy)
        (destination / f"{name}.list").write_text(text, encoding="utf-8", newline="\n")
        metadata.append(item.to_dict())
    (destination / "sources.json").write_bytes(canonical_json(metadata))
    return {"sources": len(metadata), "directory": str(destination)}


def validate_command(candidate: Path | None = None) -> dict[str, object]:
    root = repository_root()
    path = (candidate or root / "candidate").resolve()
    manifest = verify_manifest(path)
    return {"build_id": manifest["build_id"], "files": len(manifest["files"])}


def diff_command() -> dict[str, object]:
    path = repository_root() / "candidate" / "reports" / "latest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["diff"]


def report_command() -> str:
    return (repository_root() / "candidate" / "reports" / "latest.md").read_text(encoding="utf-8")

