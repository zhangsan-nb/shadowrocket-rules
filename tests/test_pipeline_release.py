from __future__ import annotations

import hashlib
import subprocess

import pytest

from trusted_rules.errors import SourceFetchError, TrustedRulesError
from trusted_rules.pipeline import build
from trusted_rules.release import publish_candidate


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def test_build_is_deterministic_for_input_order(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    first = (temp_repo / "candidate" / "rules" / "proxy.list").read_bytes()

    def reversed_fetch(name, source, policy):
        text, metadata = fake_fetch(name, source, policy)
        changed = "\n".join(reversed(text.strip().splitlines())) + "\n"
        return changed, metadata

    build(temp_repo, fetch_function=reversed_fetch)
    assert (temp_repo / "candidate" / "rules" / "proxy.list").read_bytes() == first


def test_fetch_failure_keeps_last_candidate(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    before = hashlib.sha256((temp_repo / "candidate" / "metadata" / "manifest.json").read_bytes()).hexdigest()

    def fail(*args):
        raise SourceFetchError("404", key="source.http")

    with pytest.raises(SourceFetchError):
        build(temp_repo, fetch_function=fail)
    after = hashlib.sha256((temp_repo / "candidate" / "metadata" / "manifest.json").read_bytes()).hexdigest()
    assert after == before


def test_ci_mode_never_uses_bootstrap_fallback(temp_repo):
    def fail(*args):
        raise SourceFetchError("network blocked", key="source.fetch")

    with pytest.raises(SourceFetchError):
        build(temp_repo, fetch_function=fail, ci=True)


def test_ci_mode_rejects_snapshot_even_with_injected_fetcher(temp_repo, fake_fetch):
    with pytest.raises(TrustedRulesError) as caught:
        build(temp_repo, fetch_function=fake_fetch, ci=True, source_mode="snapshot")
    assert caught.value.key == "source.ci_mode"


def test_daily_pipeline_pins_both_jobs_to_event_commit(temp_repo):
    workflow = (temp_repo / ".github" / "workflows" / "daily-build.yml").read_text(encoding="utf-8")
    assert workflow.count("ref: ${{ github.sha }}") == 2
    assert "ref: main" not in workflow
    assert workflow.count('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"') == 2


def test_publish_script_expands_candidate_argument(temp_repo):
    script = (temp_repo / "scripts" / "publish.sh").read_text(encoding="utf-8")
    assert 'candidate="${1:-$repo_root/candidate-verified}"' in script
    assert 'candidate="\\${1:' not in script


def test_ci_publish_rejects_non_live_candidate(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", git(temp_repo, "rev-parse", "HEAD"))
    with pytest.raises(TrustedRulesError) as caught:
        publish_candidate(temp_repo, temp_repo / "candidate", local_only=True)
    assert caught.value.key == "artifact.source_mode_binding"


def test_two_releases_have_normal_parent_history(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    first = publish_candidate(temp_repo, temp_repo / "candidate", local_only=True)
    assert git(temp_repo, "rev-parse", "release^") == git(temp_repo, "rev-parse", "main")

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831060")
    build(temp_repo, fetch_function=fake_fetch)
    second = publish_candidate(temp_repo, temp_repo / "candidate", local_only=True)
    assert git(temp_repo, "rev-parse", f"{second}^") == first
    assert git(temp_repo, "rev-list", "--count", "main..release") == "2"


def test_build_reads_baseline_by_resolved_remote_tracking_sha(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    first = publish_candidate(temp_repo, temp_repo / "candidate", local_only=True)
    git(temp_repo, "update-ref", "refs/remotes/origin/release", first)
    git(temp_repo, "branch", "-D", "release")

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831060")
    result = build(temp_repo, fetch_function=fake_fetch)
    assert result["build"]["baseline_release_commit"] == first
