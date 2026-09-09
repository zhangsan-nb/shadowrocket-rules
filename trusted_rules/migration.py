from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_json_yaml
from .errors import SecurityGateError


def load_scope_migration(
    repo: Path,
    migration_path: Path | None,
    *,
    baseline_release: str | None,
    enabled_sources: set[str],
) -> dict[str, Any] | None:
    """Load the single, owner-approved scope migration contract.

    The contract is deliberately one-shot: once release has advanced beyond
    ``from_release``, the same migration can no longer be reused.
    """

    if migration_path is None:
        return None
    path = migration_path.resolve()
    allowed_root = (repo / "config" / "migrations").resolve()
    if not path.is_relative_to(allowed_root) or not path.is_file():
        raise SecurityGateError("范围迁移文件路径非法", key="migration.path")
    migration = load_json_yaml(path)
    if migration.get("schema_version") != 1 or not isinstance(migration.get("id"), str):
        raise SecurityGateError("范围迁移契约格式无效", key="migration.schema")
    if migration.get("from_release") != baseline_release:
        raise SecurityGateError("范围迁移不匹配当前 release 基线或已被使用", key="migration.baseline")
    required_sources = migration.get("required_sources")
    if not isinstance(required_sources, list) or set(required_sources) != enabled_sources:
        raise SecurityGateError("范围迁移没有绑定完整启用源集合", key="migration.sources")
    return migration
