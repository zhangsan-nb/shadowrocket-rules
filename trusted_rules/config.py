from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import TrustedRulesError
from .models import CATEGORIES


def load_json_yaml(path: Path) -> dict[str, Any]:
    """配置使用 JSON 语法（JSON 是 YAML 1.2 子集），避免隐式第三方解析器。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedRulesError(f"无法读取配置 {path}: {exc}", key="config.invalid") from exc
    if not isinstance(data, dict):
        raise TrustedRulesError(f"配置根节点必须是对象: {path}", key="config.invalid")
    return data


def load_lines(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TrustedRulesError(f"无法读取 {path}: {exc}", key="config.read") from exc
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def validate_policy(policy: dict[str, Any]) -> None:
    try:
        v4 = int(policy["cidr"]["min_ipv4_prefix"])
        v6 = int(policy["cidr"]["min_ipv6_prefix"])
        absolute = int(policy["anomaly"]["absolute_delta"])
        percentage = float(policy["anomaly"]["percentage_delta"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TrustedRulesError(f"policy.yml 缺少必需字段: {exc}", key="config.policy") from exc
    if not 8 <= v4 <= 32 or not 16 <= v6 <= 128:
        raise TrustedRulesError("CIDR 阈值只能比 IPv4 /8、IPv6 /16 更严格", key="config.policy")
    if absolute < 0 or percentage < 0:
        raise TrustedRulesError("异常变化阈值不得为负", key="config.policy")
    if tuple(policy.get("category_order", ())) != CATEGORIES:
        raise TrustedRulesError(
            "category_order 必须固定为 direct, reject, proxy",
            key="config.policy_order",
        )
    proof = policy.get("protected_proof", {})
    if proof.get("algorithm") != "conservative-language-signature-v1":
        raise TrustedRulesError(
            "protected_proof.algorithm 不受支持",
            key="config.protected_proof",
        )
    for category, count in policy.get("minimum_rules", {}).items():
        if category not in {"direct", "reject", "proxy"} or not isinstance(count, int) or count < 1:
            raise TrustedRulesError("minimum_rules 必须为合法类别的正整数", key="config.policy")
