from __future__ import annotations

import ipaddress
import re

from .errors import SecurityGateError
from .models import IP_TYPES, Rule

_ASCII_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or "*" in value or "/" in value or ":" in value:
        raise SecurityGateError(f"非法域名: {value!r}", key="domain.invalid")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SecurityGateError(f"IDNA 转换失败: {value!r}", key="domain.idna") from exc
    if len(value) > 253:
        raise SecurityGateError(f"域名过长: {value!r}", key="domain.invalid")
    labels = value.split(".")
    if len(labels) < 2 or any(not _ASCII_LABEL.fullmatch(label) for label in labels):
        raise SecurityGateError(f"域名 label 非法: {value!r}", key="domain.invalid")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise SecurityGateError(f"域名规则伪装成 IP: {value!r}", key="domain.ip_masquerade")


def normalize_rule(rule: Rule) -> Rule:
    value = rule.value.strip()
    if rule.rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        value = normalize_domain(value)
    elif rule.rule_type == "DOMAIN-KEYWORD":
        value = value.lower()
        if not value or len(value) > 63 or not re.fullmatch(r"[a-z0-9-]+", value):
            raise SecurityGateError(f"非法 DOMAIN-KEYWORD: {value!r}", key="keyword.invalid")
    elif rule.rule_type in IP_TYPES:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SecurityGateError(f"非法 CIDR: {value!r}", key="cidr.invalid") from exc
        expected = 4 if rule.rule_type == "IP-CIDR" else 6
        if network.version != expected:
            raise SecurityGateError(f"CIDR 地址族与类型不符: {rule.line()}", key="cidr.family")
        value = network.with_prefixlen
    elif rule.rule_type == "IP-ASN":
        token = value.upper().removeprefix("AS")
        if not token.isdigit() or not 0 < int(token) <= 4_294_967_295:
            raise SecurityGateError(f"非法 ASN: {value!r}", key="asn.invalid")
        value = token
    elif rule.rule_type == "USER-AGENT":
        if not value or len(value) > 256 or "\n" in value or "\r" in value:
            raise SecurityGateError("非法 USER-AGENT", key="user_agent.invalid")
    return Rule(rule.rule_type, value, rule.category, rule.source, rule.no_resolve)


def stable_unique(rules: list[Rule]) -> list[Rule]:
    selected: dict[tuple[str, str, str], Rule] = {}
    for rule in rules:
        selected.setdefault(rule.semantic_key, rule)
    return sorted(selected.values(), key=lambda item: (item.rule_type, item.value, item.source))
