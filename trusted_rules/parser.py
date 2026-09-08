from __future__ import annotations

import re

from .errors import SecurityGateError
from .models import Rule
from .normalize import normalize_rule

_FORBIDDEN = re.compile(
    r"(?:^\s*\[(?:mitm|script|url\s*rewrite|host|general|proxy|proxy\s*group)\]\s*$|"
    r"script-path\s*=|script-update-interval\s*=|http-request|http-response|"
    r"hostname\s*=|ca-passphrase|ca-p12|https?://)",
    re.IGNORECASE,
)


def reject_contamination(text: str) -> None:
    head = text[:4096].lower()
    cloudflare_error = (
        "cloudflare ray id" in head
        or "error 1020" in head
        or "attention required! | cloudflare" in head
    )
    if "<html" in head or "<!doctype html" in head or "404 not found" in head or cloudflare_error:
        raise SecurityGateError("输入疑似 HTML、404 或 Cloudflare 错误页", key="content.html")
    if "\x00" in text:
        raise SecurityGateError("输入包含 NUL", key="content.control")
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if any(ord(ch) < 32 and ch != "\t" for ch in line):
            raise SecurityGateError(f"第 {number} 行含控制字符", key="content.control")
        if _FORBIDDEN.search(line):
            raise SecurityGateError(f"第 {number} 行命中配置注入: {line[:80]}", key="content.injection")


def parse_rules(text: str, *, category: str, source: str, allow_types: set[str]) -> list[Rule]:
    reject_contamination(text)
    parsed: list[Rule] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", ";", "//")):
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2 or len(parts) > 3:
            raise SecurityGateError(f"{source}:{number} 规则字段数量非法", key="rule.syntax")
        rule_type = parts[0].upper()
        if rule_type not in allow_types:
            raise SecurityGateError(f"{source}:{number} 未允许的规则类型 {rule_type}", key="rule.type")
        no_resolve = False
        if len(parts) == 3:
            if parts[2].lower() != "no-resolve" or rule_type not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
                raise SecurityGateError(f"{source}:{number} 非法规则选项", key="rule.option")
            no_resolve = True
        parsed.append(normalize_rule(Rule(rule_type, parts[1], category, source, no_resolve)))
    if not parsed:
        raise SecurityGateError(f"规则源为空: {source}", key="rule.empty")
    return parsed
