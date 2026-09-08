from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from trusted_rules.models import SourceMetadata


@pytest.fixture
def allow_types() -> set[str]:
    return {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "USER-AGENT"}


@pytest.fixture
def fake_fetch():
    def run(name, source, policy):
        lines = ["DOMAIN-SUFFIX,openai.com"]
        lines.extend(f"DOMAIN,p{index}.openai.com" for index in range(34))
        text = "\n".join(lines) + "\n"
        raw = text.encode()
        return text, SourceMetadata(
            name=name,
            url=source["url"],
            fetched_at=datetime(2026, 9, 8, tzinfo=timezone.utc).isoformat(),
            http_status=200,
            content_length=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
            etag='"fixture"',
            last_modified=None,
            git_commit=None,
        )

    return run


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repo"
    repo.mkdir()
    for directory in ("config", "trusted_rules", "scripts", ".github"):
        path = source / directory
        if path.exists():
            shutil.copytree(path, repo / directory)
    for filename in (".gitignore", "requirements.txt", "PROJECT_SPEC.md"):
        path = source / filename
        if path.exists():
            shutil.copy2(path, repo / filename)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    return repo
