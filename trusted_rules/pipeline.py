from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .artifacts import canonical_json, git_output, release_commit, sha256_file, source_commit, verify_manifest, write_manifest
from .config import load_json_yaml, load_lines, validate_policy
from .errors import SecurityGateError, TrustedRulesError
from .fetcher import fetch_source
from .gates import PublicSuffixes, merge_manual, run_gates
from .models import CATEGORIES, GateResult, Rule, SourceMetadata
from .normalize import normalize_domain, stable_unique
from .parser import parse_rules

FetchFunction = Callable[[str, dict[str, Any], dict[str, Any]], tuple[str, SourceMetadata]]


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        return datetime.fromtimestamp(int(epoch), timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _tree_digest(root: Path, relative_paths: list[str]) -> str:
    digest = hashlib.sha256()
    files: list[Path] = []
    for relative in relative_paths:
        path = root / relative
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file() and "__pycache__" not in item.parts)
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _read_release_rules(repo: Path, allow_types: set[str]) -> list[Rule] | None:
    if release_commit(repo) is None:
        return None
    rules: list[Rule] = []
    for category in CATEGORIES:
        text = git_output(repo, "show", f"release:rules/{category}.list", allow_failure=True)
        if text is None:
            raise SecurityGateError("release 分支缺少规则文件", key="baseline.incomplete")
        rules.extend(parse_rules(text, category=category, source="baseline", allow_types=allow_types))
    return stable_unique(rules)


def _render_rules(category: str, rules: list[Rule], generated_at: str) -> str:
    lines = [
        f"# NAME: {category.capitalize()}",
        f"# GENERATED: {generated_at}",
        "# DO NOT EDIT",
        "# ORDER: direct -> reject -> proxy -> GEOIP CN -> FINAL",
        "",
    ]
    lines.extend(rule.line() for rule in rules if rule.category == category)
    return "\n".join(lines) + "\n"


def _report_payload(
    build_id: str,
    generated_at: str,
    source_sha: str,
    baseline_sha: str | None,
    metadata: list[SourceMetadata],
    gates: list[GateResult],
    diff: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "build_id": build_id,
        "generated_at": generated_at,
        "source_commit": source_sha,
        "baseline_release_commit": baseline_sha,
        "result": "PASS",
        "published": False,
        "sources": [item.to_dict() for item in metadata],
        "gates": [item.to_dict() for item in gates],
        "diff": diff,
        "policy_changes": [],
        "protected_domain_changes": [],
        "conflicts": [],
    }


def _report_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Shadowrocket Trusted Rules Audit",
        "",
        f"- Build: {payload['generated_at']}",
        f"- Build ID: {payload['build_id']}",
        f"- Result: {payload['result']}",
        f"- Published: {'YES' if payload['published'] else 'NO (candidate)'}",
        "",
        "## Source status",
        "",
    ]
    for source in payload["sources"]:
        lines.append(f"- {source['name']}: PASS, bytes={source['content_length']}, sha256={source['sha256']}")
    lines.extend(["", "## Security gates", ""])
    for gate in payload["gates"]:
        detail = f" — {gate['detail']}" if gate["detail"] else ""
        lines.append(f"- {gate['name']}: {gate['status']}{detail}")
    for category in CATEGORIES:
        item = payload["diff"][category]
        lines.extend(
            [
                "",
                f"## {category.upper()}",
                "",
                f"- Previous: {item['previous']}",
                f"- Current: {item['current']}",
                f"- Added: {item['added_count']}",
                f"- Removed: {item['removed_count']}",
                f"- Delta: {item['percentage_delta']}%",
                "",
                "### Added rules",
                "",
                *([f"- {line}" for line in item["added"]] or ["- None"]),
                "",
                "### Removed rules",
                "",
                *([f"- {line}" for line in item["removed"]] or ["- None"]),
            ]
        )
    lines.extend(["", "## Policy changes", "", "- None", "", "## Protected domain changes", "", "- None", "", "## Conflicts", "", "- None", ""])
    return "\n".join(lines)


def _verify_psl_pin(repo: Path) -> str:
    path = repo / "config" / "public_suffix_list.dat"
    expected = (repo / "config" / "public_suffix_list.sha256").read_text(encoding="utf-8").strip()
    actual = sha256_file(path)
    if expected != actual:
        raise SecurityGateError("Public Suffix 快照哈希不匹配", key="psl.hash")
    return actual


def _load_bootstrap_snapshot(repo: Path, name: str, source: dict[str, Any]) -> tuple[str, SourceMetadata]:
    relative = Path(str(source["bootstrap_path"]))
    path = (repo / relative).resolve()
    allowed_root = (repo / "config" / "bootstrap").resolve()
    if not path.is_relative_to(allowed_root) or not path.is_file():
        raise SecurityGateError(f"{name} 的 bootstrap 路径非法", key="source.bootstrap_path")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != source.get("bootstrap_sha256"):
        raise SecurityGateError(f"{name} 的 bootstrap SHA-256 不匹配", key="source.bootstrap_hash")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SecurityGateError(f"{name} 的 bootstrap 不是 UTF-8", key="source.bootstrap_encoding") from exc
    return text, SourceMetadata(
        name=name,
        url=str(source["url"]),
        fetched_at=str(source["bootstrap_verified_at"]),
        http_status=200,
        content_length=len(raw),
        sha256=digest,
        etag=None,
        last_modified=None,
        git_commit=str(source["bootstrap_git_commit"]),
        fetch_mode="pinned_bootstrap_snapshot",
    )


def load_candidate_rules(candidate: Path, allow_types: set[str]) -> list[Rule]:
    rules: list[Rule] = []
    for category in CATEGORIES:
        path = candidate / "rules" / f"{category}.list"
        rules.extend(parse_rules(path.read_text(encoding="utf-8"), category=category, source="candidate", allow_types=allow_types))
    return stable_unique(rules)


def build(
    repo: Path | None = None,
    *,
    output: Path | None = None,
    fetch_function: FetchFunction = fetch_source,
    ci: bool = False,
) -> dict[str, Any]:
    repo = (repo or repository_root()).resolve()
    output = (output or repo / "candidate").resolve()
    if output.parent != repo:
        raise TrustedRulesError("候选目录必须是仓库根目录的直接子目录", key="artifact.output")
    sources_config = load_json_yaml(repo / "config" / "sources.yml")
    policy = load_json_yaml(repo / "config" / "policy.yml")
    validate_policy(policy)
    allow_types = set(load_lines(repo / "config" / "allow_rule_types.txt"))
    protected = {normalize_domain(item) for item in load_lines(repo / "config" / "protected_domains.txt")}
    psl_hash = _verify_psl_pin(repo)
    psl = PublicSuffixes.load(repo / "config" / "public_suffix_list.dat")
    previous = _read_release_rules(repo, allow_types)

    upstream: list[Rule] = []
    source_metadata: list[SourceMetadata] = []
    source_counts: dict[str, int] = {}
    for name, source in sources_config.get("sources", {}).items():
        if not source.get("enabled", False):
            continue
        if source.get("type") != "shadowrocket_ruleset" or source.get("category") not in CATEGORIES:
            raise TrustedRulesError(f"源 {name} 的类型或类别不受支持", key="source.config")
        if not ci and fetch_function is fetch_source and source.get("bootstrap_path"):
            text, metadata = _load_bootstrap_snapshot(repo, name, source)
        else:
            text, metadata = fetch_function(name, source, policy)
        parsed = parse_rules(text, category=source["category"], source=name, allow_types=allow_types)
        source_counts[name] = len(parsed)
        upstream.extend(parsed)
        source_metadata.append(metadata)
    if not source_metadata:
        raise TrustedRulesError("没有启用的上游源", key="source.none")

    manual: list[Rule] = []
    for category in CATEGORIES:
        path = repo / "config" / "manual" / f"{category}.list"
        text = path.read_text(encoding="utf-8")
        content_lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", ";", "//"))]
        if content_lines:
            manual.extend(parse_rules(text, category=category, source=f"manual_{category}", allow_types=allow_types))
    merged_rules = merge_manual(upstream, manual)
    origins: dict[str, list[str]] = {}
    for rule in merged_rules:
        key = f"{rule.category}:{rule.line()}"
        origins.setdefault(key, [])
        if rule.source not in origins[key]:
            origins[key].append(rule.source)
    rules = stable_unique(merged_rules)
    gates, diff = run_gates(rules, previous, policy, protected, psl, source_counts)

    generated_at = _timestamp()
    source_sha = source_commit(repo)
    baseline_sha = release_commit(repo)
    build_id = hashlib.sha256(
        canonical_json(
            {
                "source_commit": source_sha,
                "baseline_release_commit": baseline_sha,
                "generated_at": generated_at,
                "sources": [item.sha256 for item in source_metadata],
            }
        )
    ).hexdigest()[:20]

    temporary = Path(tempfile.mkdtemp(prefix=".candidate-", dir=repo))
    backup = repo / ".candidate-backup"
    try:
        for directory in ("rules", "reports/history", "metadata"):
            (temporary / directory).mkdir(parents=True, exist_ok=True)
        for category in CATEGORIES:
            (temporary / "rules" / f"{category}.list").write_text(
                _render_rules(category, rules, generated_at),
                encoding="utf-8",
                newline="\n",
            )
        (temporary / "metadata" / "sources.json").write_bytes(canonical_json([item.to_dict() for item in source_metadata]))
        (temporary / "metadata" / "rule_origins.json").write_bytes(canonical_json(origins))
        gate_digest = hashlib.sha256(canonical_json([item.to_dict() for item in gates])).hexdigest()
        normalized_digest = hashlib.sha256(
            "\n".join(f"{rule.category}:{rule.line()}" for rule in rules).encode("utf-8")
        ).hexdigest()
        config_digest = _tree_digest(repo, ["config"])
        code_digest = _tree_digest(repo, ["trusted_rules", "scripts", ".github"])
        build_payload = {
            "schema_version": 1,
            "build_id": build_id,
            "generated_at": generated_at,
            "source_commit": source_sha,
            "baseline_release_commit": baseline_sha,
            "config_digest": config_digest,
            "code_digest": code_digest,
            "psl_digest": psl_hash,
            "input_digests": {item.name: item.sha256 for item in source_metadata},
            "normalized_set_digest": normalized_digest,
            "gate_result_digest": gate_digest,
            "status": "PASS",
        }
        (temporary / "metadata" / "build.json").write_bytes(canonical_json(build_payload))
        report = _report_payload(build_id, generated_at, source_sha, baseline_sha, source_metadata, gates, diff)
        (temporary / "reports" / "latest.json").write_bytes(canonical_json(report))
        markdown = _report_markdown(report)
        (temporary / "reports" / "latest.md").write_text(markdown, encoding="utf-8", newline="\n")
        history_name = generated_at.replace(":", "-").replace("+", "_") + ".json"
        (temporary / "reports" / "history" / history_name).write_bytes(canonical_json(report))
        hash_targets = [temporary / "rules" / f"{category}.list" for category in CATEGORIES]
        hash_targets += [temporary / "reports" / "latest.json", temporary / "reports" / "latest.md"]
        hashes = {path.relative_to(temporary).as_posix(): sha256_file(path) for path in hash_targets}
        (temporary / "metadata" / "hashes.json").write_bytes(canonical_json(hashes))
        identity = {
            "build_id": build_id,
            "source_commit": source_sha,
            "baseline_release_commit": baseline_sha,
            "config_digest": config_digest,
            "code_digest": code_digest,
            "psl_digest": psl_hash,
            "input_digests": build_payload["input_digests"],
            "normalized_set_digest": normalized_digest,
            "gate_result_digest": gate_digest,
        }
        write_manifest(temporary, identity)
        verify_manifest(temporary, expected_source_sha=source_sha)
        if backup.exists():
            shutil.rmtree(backup)
        if output.exists():
            output.replace(backup)
        temporary.replace(output)
        if backup.exists():
            shutil.rmtree(backup)
        return {
            "candidate": str(output),
            "build": build_payload,
            "counts": {category: sum(rule.category == category for rule in rules) for category in CATEGORIES},
        }
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        if backup.exists() and not output.exists():
            backup.replace(output)
        raise
