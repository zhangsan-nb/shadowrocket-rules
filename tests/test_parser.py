from __future__ import annotations

import pytest

from trusted_rules.errors import SecurityGateError
from trusted_rules.models import Rule
from trusted_rules.normalize import normalize_rule
from trusted_rules.parser import parse_rules


def test_domain_and_cidr_normalize(allow_types):
    rules = parse_rules(
        "DOMAIN-SUFFIX,OpenAI.COM\nIP-CIDR,1.2.3.1/24,no-resolve\n",
        category="proxy",
        source="test",
        allow_types=allow_types,
    )
    assert [rule.line() for rule in rules] == ["DOMAIN-SUFFIX,openai.com", "IP-CIDR,1.2.3.0/24,no-resolve"]


@pytest.mark.parametrize(
    "payload,key",
    [
        ("[MITM]\nhostname = *\n", "content.injection"),
        ("[Script]\n", "content.injection"),
        ("<html>404</html>", "content.html"),
        ("404 Not Found", "content.html"),
        ("https://evil.invalid/script.js", "content.injection"),
        ("UNKNOWN,example.com", "rule.type"),
        ("DOMAIN-SUFFIX,*", "domain.invalid"),
        ("DOMAIN,127.0.0.1", "domain.ip_masquerade"),
    ],
)
def test_malicious_or_unknown_input_fails(payload, key, allow_types):
    with pytest.raises(SecurityGateError) as caught:
        parse_rules(payload, category="proxy", source="evil", allow_types=allow_types)
    assert caught.value.key == key


def test_unknown_option_fails(allow_types):
    with pytest.raises(SecurityGateError, match="非法规则选项"):
        parse_rules("DOMAIN,example.com,foo", category="proxy", source="test", allow_types=allow_types)


def test_ipv6_family_mismatch_fails():
    with pytest.raises(SecurityGateError):
        normalize_rule(Rule("IP-CIDR6", "1.2.3.4/24", "proxy", "test"))
