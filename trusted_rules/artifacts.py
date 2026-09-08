from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import SecurityGateError, TrustedRulesError

ALLOWED_TOP_LEVEL = frozenset({"rules", "reports", "metadata"})


def canonical_json(data: Any) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_files(root: Path, *, include_manifest: bool = True) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SecurityGateError(f"候选制品禁止 symlink: {path}", key="artifact.symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        pure = PurePosixPath(relative.as_posix())
        if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] not in ALLOWED_TOP_LEVEL:
            raise SecurityGateError(f"候选制品路径非法: {relative}", key="artifact.path")
        if not include_manifest and pure.as_posix() == "metadata/manifest.json":
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def manifest_entries(root: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in safe_files(root, include_manifest=False)
    ]


def write_manifest(root: Path, identity: dict[str, Any]) -> dict[str, Any]:
    manifest = {"schema_version": 1, **identity, "files": manifest_entries(root)}
    path = root / "metadata" / "manifest.json"
    path.write_bytes(canonical_json(manifest))
    return manifest


def verify_manifest(root: Path, *, expected_source_sha: str | None = None, expected_baseline_sha: str | None = None) -> dict[str, Any]:
    path = root / "metadata" / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityGateError(f"manifest 不可读: {exc}", key="artifact.manifest") from exc
    if expected_source_sha and manifest.get("source_commit") != expected_source_sha:
        raise SecurityGateError("候选 source commit 与发布运行不一致", key="artifact.source_binding")
    if expected_baseline_sha is not None and manifest.get("baseline_release_commit") != expected_baseline_sha:
        raise SecurityGateError("候选 baseline 与当前 release 不一致", key="artifact.baseline_binding")
    actual = manifest_entries(root)
    if manifest.get("files") != actual:
        raise SecurityGateError("候选文件集合、大小或 SHA-256 与 manifest 不一致", key="artifact.hash")
    listed = {entry["path"] for entry in actual} | {"metadata/manifest.json"}
    observed = {path.relative_to(root).as_posix() for path in safe_files(root)}
    if listed != observed:
        raise SecurityGateError("候选存在缺失或额外文件", key="artifact.file_set")
    return manifest


def git_output(repo: Path, *args: str, allow_failure: bool = False) -> str | None:
    import subprocess

    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode:
        if allow_failure:
            return None
        raise TrustedRulesError(f"git {' '.join(args)} 失败: {completed.stderr.strip()}", key="git.command")
    return completed.stdout.strip()


def source_commit(repo: Path) -> str:
    override = os.environ.get("GITHUB_SHA")
    if override:
        return override
    return git_output(repo, "rev-parse", "HEAD") or "UNKNOWN"


def release_commit(repo: Path) -> str | None:
    local = git_output(repo, "rev-parse", "--verify", "refs/heads/release", allow_failure=True)
    if local:
        return local
    return git_output(repo, "rev-parse", "--verify", "refs/remotes/origin/release", allow_failure=True)
