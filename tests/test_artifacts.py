from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from trusted_rules.artifacts import verify_manifest
from trusted_rules.errors import SecurityGateError
from trusted_rules.pipeline import build
from trusted_rules.seal import seal_candidate, verify_and_extract


def test_manifest_detects_tamper(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    candidate = temp_repo / "candidate"
    verify_manifest(candidate)
    with (candidate / "rules" / "proxy.list").open("a", encoding="utf-8") as handle:
        handle.write("DOMAIN,evil.example.com\n")
    with pytest.raises(SecurityGateError):
        verify_manifest(candidate)


def test_manifest_binds_source_mode_policy_order_and_proof_semantics(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    manifest = json.loads((temp_repo / "candidate" / "metadata" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_resolution_mode"] == "injected_test_fetcher"
    assert manifest["category_order"] == ["direct", "reject", "proxy"]
    assert manifest["matcher_semantics_version"] == "category-first-domain-language-v1"
    for field in (
        "source_commit",
        "baseline_release_commit",
        "config_digest",
        "code_digest",
        "psl_digest",
        "input_digests",
        "normalized_set_digest",
        "gate_result_digest",
        "static_exclusions",
        "files",
    ):
        assert field in manifest


def test_manifest_rejects_stripped_identity_field(temp_repo, fake_fetch, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    path = temp_repo / "candidate" / "metadata" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    del manifest["source_resolution_mode"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SecurityGateError) as caught:
        verify_manifest(temp_repo / "candidate")
    assert caught.value.key == "artifact.identity"


def test_sealed_bundle_detects_transport_tamper(temp_repo, fake_fetch, monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788831000")
    build(temp_repo, fetch_function=fake_fetch)
    archive = tmp_path / "candidate.zip"
    digest = tmp_path / "candidate.zip.sha256"
    seal_candidate(temp_repo / "candidate", archive, digest)
    archive.write_bytes(archive.read_bytes() + b"x")
    with pytest.raises(SecurityGateError):
        verify_and_extract(archive, digest, tmp_path / "out")


def test_archive_path_traversal_is_blocked(tmp_path):
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape", b"x")
    digest = tmp_path / "candidate.zip.sha256"
    digest.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  candidate.zip\n", encoding="utf-8")
    with pytest.raises(SecurityGateError):
        verify_and_extract(archive, digest, tmp_path / "out")
