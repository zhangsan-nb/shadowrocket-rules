from __future__ import annotations

import hashlib
import json
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
from .migration import load_scope_migration
from .models import CATEGORIES, MATCHER_SEMANTICS_VERSION, GateResult, Rule, SourceMetadata
from .normalize import normalize_domain, stable_unique
from .parser import parse_domain_set, parse_rules

FetchFunction = Callable[[str, dict[str, Any], dict[str, Any]], tuple[str, SourceMetadata]]
LEGACY_V1_PROOF_BINDINGS = frozenset(
    {
        (
            "801a48a157fdea746b18a56fbb29f3b8ba08f91d",
            "5c686312e137305e178f70e806869111a16d807ce73b184feb82d4322b92cf98",
        )
    }
)


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


def _read_release_baseline(
    repo: Path,
    allow_types: set[str],
) -> tuple[list[Rule] | None, tuple[str, ...] | None, str | None]:
    baseline_sha = release_commit(repo)
    if baseline_sha is None:
        return None, None, None
    rules: list[Rule] = []
    for category in CATEGORIES:
        text = git_output(repo, "show", f"{baseline_sha}:rules/{category}.list", allow_failure=True)
        if text is None:
            raise SecurityGateError("release 分支缺少规则文件", key="baseline.incomplete")
        rules.extend(parse_rules(text, category=category, source="baseline", allow_types=allow_types))
    raw_build = git_output(repo, "show", f"{baseline_sha}:metadata/build.json", allow_failure=True)
    if raw_build is None:
        raise SecurityGateError("release 分支缺少构建身份元数据", key="baseline.identity_missing")
    try:
        build_identity = json.loads(raw_build)
    except json.JSONDecodeError as exc:
        raise SecurityGateError("release 构建身份元数据无效", key="baseline.identity_invalid") from exc
    baseline_order = build_identity.get("category_order")
    baseline_matcher = build_identity.get("matcher_semantics_version")
    legacy_identity = (build_identity.get("source_commit"), build_identity.get("code_digest"))
    if baseline_order is None and build_identity.get("schema_version") == 1 and legacy_identity in LEGACY_V1_PROOF_BINDINGS:
        # 仅对仓库中已审计的首个 V1 release 做一次性迁移；未知 V1 身份仍失败关闭。
        baseline_order = list(CATEGORIES)
        baseline_matcher = MATCHER_SEMANTICS_VERSION
    if tuple(baseline_order or ()) != CATEGORIES or baseline_matcher != MATCHER_SEMANTICS_VERSION:
        raise SecurityGateError("release 受保护域证明契约缺失或不受支持", key="baseline.proof_contract")
    return stable_unique(rules), tuple(baseline_order), str(baseline_matcher)


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
    scope_migration: dict[str, Any] | None = None,
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
        "policy_changes": [scope_migration] if scope_migration else [],
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


def _parse_source(text: str, source: dict[str, Any], name: str, allow_types: set[str]) -> list[Rule]:
    source_type = str(source.get("type", ""))
    category = str(source.get("category", ""))
    if source_type == "shadowrocket_ruleset":
        return parse_rules(text, category=category, source=name, allow_types=allow_types)
    if source_type == "domain_set":
        return parse_domain_set(text, category=category, source=name)
    raise TrustedRulesError(f"源 {name} 的类型不受支持: {source_type}", key="source.config")


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
    source_mode: str | None = None,
    scope_migration_path: Path | None = None,
) -> dict[str, Any]:
    repo = (repo or repository_root()).resolve()
    output = (output or repo / "candidate").resolve()
    if output.parent != repo:
        raise TrustedRulesError("候选目录必须是仓库根目录的直接子目录", key="artifact.output")
    sources_config = load_json_yaml(repo / "config" / "sources.yml")
    policy = load_json_yaml(repo / "config" / "policy.yml")
    validate_policy(policy)
    # All routine builds consume current HTTPS input. Snapshot mode remains an
    # explicitly requested forensic/reproducibility path for sources that
    # carry a committed, hash-pinned bootstrap file.
    selected_source_mode = source_mode or "live"
    if selected_source_mode not in {"live", "snapshot"}:
        raise TrustedRulesError("source_mode 必须是 live 或 snapshot", key="source.mode")
    if ci and selected_source_mode != "live":
        raise TrustedRulesError("CI 只允许 live HTTPS 输入，禁止快照模式", key="source.ci_mode")
    if scope_migration_path is not None and not ci and fetch_function is fetch_source:
        raise SecurityGateError("范围迁移只能由 CI 手动审批工作流执行", key="migration.execution")
    source_resolution_mode = (
        "injected_test_fetcher"
        if fetch_function is not fetch_source
        else "live_https" if selected_source_mode == "live" else "pinned_snapshot"
    )
    allow_types = set(load_lines(repo / "config" / "allow_rule_types.txt"))
    protected = {normalize_domain(item) for item in load_lines(repo / "config" / "protected_domains.txt")}
    psl_hash = _verify_psl_pin(repo)
    psl = PublicSuffixes.load(repo / "config" / "public_suffix_list.dat")
    previous, previous_category_order, previous_matcher_version = _read_release_baseline(repo, allow_types)

    upstream: list[Rule] = []
    source_metadata: list[SourceMetadata] = []
    source_counts: dict[str, int] = {}
    for name, source in sources_config.get("sources", {}).items():
        if not source.get("enabled", False):
            continue
        if source.get("type") not in {"shadowrocket_ruleset", "domain_set"} or source.get("category") not in CATEGORIES:
            raise TrustedRulesError(f"源 {name} 的类型或类别不受支持", key="source.config")
        if fetch_function is not fetch_source:
            text, metadata = fetch_function(name, source, policy)
        elif selected_source_mode == "snapshot":
            if not source.get("bootstrap_path"):
                raise SecurityGateError(f"源 {name} 没有固定快照", key="source.bootstrap_missing")
            text, metadata = _load_bootstrap_snapshot(repo, name, source)
        else:
            text, metadata = fetch_function(name, source, policy)
        parsed = _parse_source(text, source, name, allow_types)
        source_counts[name] = len(parsed)
        upstream.extend(parsed)
        source_metadata.append(metadata)
    if not source_metadata:
        raise TrustedRulesError("没有启用的上游源", key="source.none")
    scope_migration = load_scope_migration(
        repo,
        scope_migration_path,
        baseline_release=release_commit(repo),
        enabled_sources=set(source_counts),
    )

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
    category_order = tuple(policy["category_order"])
    gates, diff = run_gates(
        rules,
        previous,
        policy,
        protected,
        psl,
        source_counts,
        current_category_order=category_order,
        previous_category_order=previous_category_order,
        current_matcher_version=MATCHER_SEMANTICS_VERSION,
        previous_matcher_version=previous_matcher_version,
        scope_migration=scope_migration,
    )

    generated_at = _timestamp()
    source_sha = source_commit(repo)
    baseline_sha = release_commit(repo)
    build_id = hashlib.sha256(
        canonical_json(
            {
                "source_commit": source_sha,
                "baseline_release_commit": baseline_sha,
                "generated_at": generated_at,
                "source_resolution_mode": source_resolution_mode,
                "sources": [item.sha256 for item in source_metadata],
                "scope_migration": scope_migration["id"] if scope_migration else None,
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
            "source_resolution_mode": source_resolution_mode,
            "category_order": list(category_order),
            "matcher_semantics_version": MATCHER_SEMANTICS_VERSION,
            "config_digest": config_digest,
            "code_digest": code_digest,
            "psl_digest": psl_hash,
            "input_digests": {item.name: item.sha256 for item in source_metadata},
            "normalized_set_digest": normalized_digest,
            "gate_result_digest": gate_digest,
            "status": "PASS",
            "scope_migration": scope_migration["id"] if scope_migration else None,
        }
        (temporary / "metadata" / "build.json").write_bytes(canonical_json(build_payload))
        report = _report_payload(build_id, generated_at, source_sha, baseline_sha, source_metadata, gates, diff, scope_migration)
        report["source_resolution_mode"] = source_resolution_mode
        report["category_order"] = list(category_order)
        report["matcher_semantics_version"] = MATCHER_SEMANTICS_VERSION
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
            "source_resolution_mode": source_resolution_mode,
            "category_order": list(category_order),
            "matcher_semantics_version": MATCHER_SEMANTICS_VERSION,
            "config_digest": config_digest,
            "code_digest": code_digest,
            "psl_digest": psl_hash,
            "input_digests": build_payload["input_digests"],
            "normalized_set_digest": normalized_digest,
            "gate_result_digest": gate_digest,
            "scope_migration": scope_migration["id"] if scope_migration else None,
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
