from __future__ import annotations

import hashlib
import subprocess

import pytest

from trusted_rules.errors import SourceFetchError
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
