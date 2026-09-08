from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .artifacts import git_output, release_commit, verify_manifest
from .errors import SecurityGateError, TrustedRulesError


def _run(repo: Path, *args: str, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode and not allow_failure:
        raise TrustedRulesError(f"git {' '.join(args)} 失败: {completed.stderr.strip()}", key="release.git")
    return completed


def _clear_worktree(worktree: Path) -> None:
    for item in worktree.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir() and not item.is_symlink():
            shutil.rmtree(item)
        else:
            item.unlink()


def _remote_release(repo: Path) -> str | None:
    if git_output(repo, "remote", "get-url", "origin", allow_failure=True) is None:
        return None
    _run(repo, "fetch", "--no-tags", "origin", "refs/heads/release:refs/remotes/origin/release", allow_failure=True)
    return git_output(repo, "rev-parse", "--verify", "refs/remotes/origin/release", allow_failure=True)


def publish_candidate(repo: Path, candidate: Path, *, local_only: bool = False) -> str:
    repo = repo.resolve()
    candidate = candidate.resolve()
    manifest = verify_manifest(
        candidate,
        expected_source_sha=os.environ.get("GITHUB_SHA"),
        expected_source_mode="live_https" if os.environ.get("GITHUB_ACTIONS") == "true" else None,
    )
    source_sha = str(manifest.get("source_commit", ""))
    if git_output(repo, "cat-file", "-e", f"{source_sha}^{{commit}}", allow_failure=True) is None:
        raise SecurityGateError("manifest source commit 在仓库中不存在", key="release.source")
    local_branch = git_output(repo, "rev-parse", "--verify", "refs/heads/release", allow_failure=True)
    local_baseline = release_commit(repo)
    remote_baseline = None if local_only else _remote_release(repo)
    expected_baseline = remote_baseline if remote_baseline is not None else local_baseline
    if manifest.get("baseline_release_commit") != expected_baseline:
        raise SecurityGateError("候选基线已陈旧，必须重新验证", key="release.stale_baseline")

    temporary_root = Path(tempfile.mkdtemp(prefix="trusted-release-", dir=repo.parent))
    worktree = temporary_root / "tree"
    parent = expected_baseline or source_sha
    try:
        _run(repo, "worktree", "add", "--detach", str(worktree), parent)
        _clear_worktree(worktree)
        for directory in ("rules", "reports", "metadata"):
            shutil.copytree(candidate / directory, worktree / directory)
        _run(worktree, "add", "--all")
        build_id = str(manifest["build_id"])
        _run(
            worktree,
            "-c",
            "user.name=trusted-rules-bot",
            "-c",
            "user.email=trusted-rules-bot@users.noreply.github.com",
            "commit",
            "-m",
            f"Trusted rules release {build_id}",
        )
        new_sha = git_output(worktree, "rev-parse", "HEAD")
        if not new_sha:
            raise TrustedRulesError("无法读取 release commit", key="release.commit")
        _run(repo, "worktree", "remove", "--force", str(worktree))
        old_value = local_branch or ("0" * 40)
        _run(repo, "update-ref", "refs/heads/release", new_sha, old_value)
        if not local_only and git_output(repo, "remote", "get-url", "origin", allow_failure=True):
            pushed = _run(repo, "push", "origin", f"{new_sha}:refs/heads/release", allow_failure=True)
            _run(repo, "fetch", "--no-tags", "origin", "refs/heads/release:refs/remotes/origin/release")
            observed = git_output(repo, "rev-parse", "refs/remotes/origin/release")
            if observed != new_sha:
                raise TrustedRulesError(
                    f"push 结果无法确认（exit={pushed.returncode}，remote={observed}）",
                    key="release.push_unknown",
                )
            remote_manifest = git_output(repo, "show", f"{observed}:metadata/manifest.json")
            local_manifest = (candidate / "metadata" / "manifest.json").read_text(encoding="utf-8").strip()
            if remote_manifest != local_manifest or json.loads(remote_manifest or "{}").get("build_id") != build_id:
                raise SecurityGateError("远端 release manifest 与候选不一致", key="release.remote_identity")
        return new_sha
    finally:
        if worktree.exists():
            _run(repo, "worktree", "remove", "--force", str(worktree), allow_failure=True)
        shutil.rmtree(temporary_root, ignore_errors=True)


def rollback_release(repo: Path, target: str, *, local_only: bool = False) -> str:
    current = release_commit(repo)
    if not current:
        raise TrustedRulesError("release 分支不存在", key="release.missing")
    for directory in ("rules", "reports", "metadata"):
        if git_output(repo, "cat-file", "-e", f"{target}:{directory}", allow_failure=True) is None:
            raise TrustedRulesError(f"回滚目标缺少 {directory}", key="release.rollback_target")
    temporary_root = Path(tempfile.mkdtemp(prefix="trusted-rollback-", dir=repo.parent))
    worktree = temporary_root / "tree"
    try:
        _run(repo, "worktree", "add", "--detach", str(worktree), current)
        _clear_worktree(worktree)
        for directory in ("rules", "reports", "metadata"):
            _run(worktree, "checkout", target, "--", directory)
        _run(worktree, "add", "--all")
        _run(
            worktree,
            "-c",
            "user.name=trusted-rules-bot",
            "-c",
            "user.email=trusted-rules-bot@users.noreply.github.com",
            "commit",
            "-m",
            f"Rollback trusted rules to {target[:12]}",
        )
        new_sha = git_output(worktree, "rev-parse", "HEAD") or ""
        _run(repo, "worktree", "remove", "--force", str(worktree))
        _run(repo, "update-ref", "refs/heads/release", new_sha, current)
        if not local_only and git_output(repo, "remote", "get-url", "origin", allow_failure=True):
            _run(repo, "push", "origin", f"{new_sha}:refs/heads/release")
        return new_sha
    finally:
        if worktree.exists():
            _run(repo, "worktree", "remove", "--force", str(worktree), allow_failure=True)
        shutil.rmtree(temporary_root, ignore_errors=True)
