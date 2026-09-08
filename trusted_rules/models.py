from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

CATEGORIES = ("direct", "reject", "proxy")
DOMAIN_TYPES = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"})
IP_TYPES = frozenset({"IP-CIDR", "IP-CIDR6"})


@dataclass(frozen=True, order=True)
class Rule:
    rule_type: str
    value: str
    category: str
    source: str
    no_resolve: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return self.rule_type, self.value

    @property
    def semantic_key(self) -> tuple[str, str, str]:
        return self.category, self.rule_type, self.value

    def line(self) -> str:
        suffix = ",no-resolve" if self.no_resolve and self.rule_type in (IP_TYPES | {"IP-ASN"}) else ""
        return f"{self.rule_type},{self.value}{suffix}"


@dataclass(frozen=True)
class SourceMetadata:
    name: str
    url: str
    fetched_at: str
    http_status: int
    content_length: int
    sha256: str
    etag: str | None
    last_modified: str | None
    git_commit: str | None
    fetch_mode: str = "network"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateResult:
    name: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
