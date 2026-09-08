from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import PolicyConflictError, SecurityGateError
from .models import CATEGORIES, DOMAIN_TYPES, IP_TYPES, GateResult, Rule


@dataclass(frozen=True)
class PublicSuffixes:
    exact: frozenset[str]
    wildcard: frozenset[str]
    exceptions: frozenset[str]

    @classmethod
    def load(cls, path: Path) -> "PublicSuffixes":
        exact: set[str] = set()
        wildcard: set[str] = set()
        exceptions: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip().lower()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                exceptions.add(line[1:])
            elif line.startswith("*."):
                wildcard.add(line[2:])
            else:
                exact.add(line)
        if not exact:
            raise SecurityGateError("Public Suffix 快照为空", key="psl.empty")
        return cls(frozenset(exact), frozenset(wildcard), frozenset(exceptions))

    def is_public_suffix(self, domain: str) -> bool:
        if domain in self.exceptions:
            return False
        if domain in self.exact:
            return True
        labels = domain.split(".")
        return len(labels) >= 2 and ".".join(labels[1:]) in self.wildcard


def merge_manual(upstream: list[Rule], manual: list[Rule]) -> list[Rule]:
    owners: dict[tuple[str, str], str] = {}
    for rule in manual:
        previous = owners.setdefault(rule.key, rule.category)
        if previous != rule.category:
            raise PolicyConflictError(
                f"手工规则 {rule.rule_type},{rule.value} 同时属于 {previous}/{rule.category}",
                key="manual.conflict",
            )
    manual_keys = set(owners)
    return [rule for rule in upstream if rule.key not in manual_keys] + manual


def _domain_overlap(left: Rule, right: Rule) -> bool:
    if left.rule_type == "DOMAIN" and right.rule_type == "DOMAIN":
        return left.value == right.value
    if left.rule_type == "DOMAIN":
        if right.rule_type == "DOMAIN-SUFFIX":
            return left.value == right.value or left.value.endswith("." + right.value)
        return right.value in left.value
    if right.rule_type == "DOMAIN":
        return _domain_overlap(right, left)
    if left.rule_type == "DOMAIN-SUFFIX" and right.rule_type == "DOMAIN-SUFFIX":
        return (
            left.value == right.value
            or left.value.endswith("." + right.value)
            or right.value.endswith("." + left.value)
        )
    # 任意非空 keyword 都可作为另一个 suffix 的新子域 label，两个 keyword 也可共同出现。
    return True


def rules_overlap(left: Rule, right: Rule) -> bool:
    if left.rule_type in DOMAIN_TYPES and right.rule_type in DOMAIN_TYPES:
        return _domain_overlap(left, right)
    if left.rule_type in IP_TYPES and right.rule_type in IP_TYPES:
        if left.rule_type != right.rule_type:
            return False
        return ipaddress.ip_network(left.value).overlaps(ipaddress.ip_network(right.value))
    return left.rule_type == right.rule_type and left.value == right.value


def check_cross_policy(rules: list[Rule], exceptions: list[dict[str, Any]], protected: set[str]) -> list[str]:
    exception_keys = {
        (item.get("left"), item.get("right"), item.get("winner"))
        for item in exceptions
        if item.get("reason") and item.get("winner") in CATEGORIES
    }
    conflicts: list[str] = []
    grouped = {category: [rule for rule in rules if rule.category == category] for category in CATEGORIES}
    for index, left_category in enumerate(CATEGORIES):
        for right_category in CATEGORIES[index + 1 :]:
            for left in grouped[left_category]:
                for right in grouped[right_category]:
                    if not rules_overlap(left, right):
                        continue
                    pair = (left.line(), right.line(), left_category)
                    reverse = (right.line(), left.line(), right_category)
                    protected_hit = any(
                        _rule_intersects_protected(rule, domain)
                        for rule in (left, right)
                        if rule.rule_type in DOMAIN_TYPES
                        for domain in protected
                    )
                    if not protected_hit and (pair in exception_keys or reverse in exception_keys):
                        continue
                    conflicts.append(
                        f"{left_category}:{left.line()} ↔ {right_category}:{right.line()}"
                    )
    if conflicts:
        sample = "; ".join(conflicts[:10])
        raise PolicyConflictError(f"跨策略语义冲突（共 {len(conflicts)}）: {sample}", key="policy.overlap")
    return conflicts


def _rule_intersects_protected(rule: Rule, protected: str) -> bool:
    if rule.rule_type == "DOMAIN":
        return rule.value == protected or rule.value.endswith("." + protected)
    if rule.rule_type == "DOMAIN-SUFFIX":
        return (
            rule.value == protected
            or rule.value.endswith("." + protected)
            or protected.endswith("." + rule.value)
        )
    if rule.rule_type == "DOMAIN-KEYWORD":
        # 任意合法关键字可嵌入 protected 的某个新子域；因此必须保守视作有交集。
        return True
    return False


def _protected_signature(rules: Iterable[Rule], protected: str) -> frozenset[tuple[str, str, str]]:
    return frozenset(
        (rule.category, rule.rule_type, rule.value)
        for rule in rules
        if rule.rule_type in DOMAIN_TYPES and _rule_intersects_protected(rule, protected)
    )


def check_protected_equivalence(current: list[Rule], previous: list[Rule] | None, protected: set[str]) -> GateResult:
    if previous is None:
        return GateResult("protected_domains", "N/A", "首次发布：无可信基线；其他内在门仍强制执行")
    changed: list[str] = []
    for domain in sorted(protected):
        before = _protected_signature(previous, domain)
        after = _protected_signature(current, domain)
        if before != after:
            changed.append(domain)
    if changed:
        raise SecurityGateError(
            "无法证明受保护域整个命名空间策略等价: " + ", ".join(changed),
            key="protected.changed",
        )
    return GateResult("protected_domains", "PASS", "相关规则语言签名完全相同；固定抽样不作为证明")


def check_rule_safety(rules: list[Rule], policy: dict[str, Any], psl: PublicSuffixes) -> None:
    v4_min = int(policy["cidr"]["min_ipv4_prefix"])
    v6_min = int(policy["cidr"]["min_ipv6_prefix"])
    allowed_suffixes = set(policy.get("public_suffix_exceptions", []))
    dangerous_keywords = {str(item).lower() for item in policy.get("dangerous_keywords", [".", "com"])}
    for rule in rules:
        if rule.rule_type == "DOMAIN-SUFFIX" and psl.is_public_suffix(rule.value) and rule.value not in allowed_suffixes:
            raise SecurityGateError(f"禁止公共后缀规则: {rule.line()}", key="domain.public_suffix")
        if rule.rule_type == "DOMAIN-KEYWORD" and rule.value in dangerous_keywords:
            raise SecurityGateError(f"危险 DOMAIN-KEYWORD: {rule.line()}", key="keyword.dangerous")
        if rule.rule_type in IP_TYPES:
            network = ipaddress.ip_network(rule.value)
            minimum = v4_min if network.version == 4 else v6_min
            if network.prefixlen == 0 or network.prefixlen < minimum:
                raise SecurityGateError(f"危险宽 CIDR: {rule.line()}", key="cidr.too_broad")


def calculate_diff(current: list[Rule], previous: list[Rule] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for category in CATEGORIES:
        now = {rule.line() for rule in current if rule.category == category}
        before = {rule.line() for rule in (previous or []) if rule.category == category}
        added = sorted(now - before)
        removed = sorted(before - now)
        absolute = len(added) + len(removed)
        percentage = 100.0 if not before and now else absolute / max(len(before), 1) * 100.0
        result[category] = {
            "previous": len(before),
            "current": len(now),
            "added": added,
            "removed": removed,
            "added_count": len(added),
            "removed_count": len(removed),
            "absolute_delta": absolute,
            "percentage_delta": round(percentage, 6),
        }
    return result


def run_gates(
    rules: list[Rule],
    previous: list[Rule] | None,
    policy: dict[str, Any],
    protected: set[str],
    psl: PublicSuffixes,
    source_counts: dict[str, int],
) -> tuple[list[GateResult], dict[str, Any]]:
    results: list[GateResult] = []
    if not rules:
        raise SecurityGateError("候选规则为空", key="rules.empty")
    check_rule_safety(rules, policy, psl)
    results.append(GateResult("syntax_allowlist_domain_cidr", "PASS"))
    check_cross_policy(rules, policy.get("policy_exceptions", []), protected)
    results.append(GateResult("cross_policy_conflict", "PASS"))
    results.append(check_protected_equivalence(rules, previous, protected))
    counts = {category: sum(rule.category == category for rule in rules) for category in CATEGORIES}
    for category, minimum in policy.get("minimum_rules", {}).items():
        if counts.get(category, 0) < int(minimum):
            raise SecurityGateError(
                f"{category} 规则数 {counts.get(category, 0)} 低于下限 {minimum}",
                key="rules.minimum",
            )
    for source, minimum in policy.get("minimum_rules_by_source", {}).items():
        if source_counts.get(source, 0) < int(minimum):
            raise SecurityGateError(
                f"源 {source} 规则数 {source_counts.get(source, 0)} 低于下限 {minimum}",
                key="source.minimum",
            )
    results.append(GateResult("minimum_nonempty", "PASS", str(counts)))
    diff = calculate_diff(rules, previous)
    if previous is None:
        results.append(GateResult("anomaly_delta", "N/A", "首次发布无可信数量基线"))
    else:
        absolute_limit = int(policy["anomaly"]["absolute_delta"])
        percentage_limit = float(policy["anomaly"]["percentage_delta"])
        for category, item in diff.items():
            if item["absolute_delta"] > absolute_limit or item["percentage_delta"] > percentage_limit:
                raise SecurityGateError(
                    f"{category} 变化异常: absolute={item['absolute_delta']}, percentage={item['percentage_delta']}%",
                    key="anomaly.delta",
                )
        results.append(GateResult("anomaly_delta", "PASS"))
    return results, diff

