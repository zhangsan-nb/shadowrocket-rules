from __future__ import annotations

import pytest

from trusted_rules.errors import PolicyConflictError, SecurityGateError
from trusted_rules.gates import PublicSuffixes, check_cross_policy, check_protected_equivalence, check_rule_safety, run_gates
from trusted_rules.models import Rule


def rule(kind: str, value: str, category: str) -> Rule:
    return Rule(kind, value, category, "test")


def test_public_suffix_wildcard_and_exception(tmp_path):
    path = tmp_path / "psl"
    path.write_text("com\n*.ck\n!www.ck\n", encoding="utf-8")
    psl = PublicSuffixes.load(path)
    assert psl.is_public_suffix("com")
    assert psl.is_public_suffix("foo.ck")
    assert not psl.is_public_suffix("www.ck")


def test_public_suffix_and_zero_cidr_block(tmp_path):
    path = tmp_path / "psl"
    path.write_text("com\n", encoding="utf-8")
    psl = PublicSuffixes.load(path)
    policy = {"cidr": {"min_ipv4_prefix": 8, "min_ipv6_prefix": 16}}
    with pytest.raises(SecurityGateError, match="公共后缀"):
        check_rule_safety([rule("DOMAIN-SUFFIX", "com", "proxy")], policy, psl)
    with pytest.raises(SecurityGateError, match="危险宽 CIDR"):
        check_rule_safety([rule("IP-CIDR", "0.0.0.0/0", "proxy")], policy, psl)


def test_cross_category_parent_child_conflict():
    rules = [rule("DOMAIN-SUFFIX", "example.com", "direct"), rule("DOMAIN", "api.example.com", "proxy")]
    with pytest.raises(PolicyConflictError):
        check_cross_policy(rules, [], set())


@pytest.mark.parametrize(
    "before,after",
    [
        ([rule("DOMAIN-SUFFIX", "openai.com", "proxy")], [rule("DOMAIN-SUFFIX", "openai.com", "proxy"), rule("DOMAIN", "deep.x.openai.com", "direct")]),
        ([rule("DOMAIN-KEYWORD", "deep-token", "proxy")], [rule("DOMAIN-KEYWORD", "deep-token", "direct")]),
        ([rule("DOMAIN-SUFFIX", "openai.com", "proxy")], []),
    ],
)
def test_protected_full_namespace_change_blocks(before, after):
    with pytest.raises(SecurityGateError, match="整个命名空间"):
        check_protected_equivalence(after, before, {"openai.com"})


def test_unrelated_safe_change_passes_protected_proof():
    before = [rule("DOMAIN-SUFFIX", "openai.com", "proxy"), rule("DOMAIN", "one.example.net", "proxy")]
    after = [rule("DOMAIN-SUFFIX", "openai.com", "proxy"), rule("DOMAIN", "two.example.net", "proxy")]
    result = check_protected_equivalence(after, before, {"openai.com"})
    assert result.status == "PASS"


def test_large_anomaly_blocks(tmp_path):
    psl_path = tmp_path / "psl"
    psl_path.write_text("com\n", encoding="utf-8")
    previous = [rule("DOMAIN", "base.example.com", "direct"), rule("DOMAIN", "ads.example.com", "reject"), rule("DOMAIN-SUFFIX", "openai.com", "proxy")]
    current = previous + [rule("DOMAIN", f"d{index}.example.com", "direct") for index in range(50_000)]
    policy = {
        "cidr": {"min_ipv4_prefix": 8, "min_ipv6_prefix": 16},
        "dangerous_keywords": [".", "com"],
        "minimum_rules": {"direct": 1, "reject": 1, "proxy": 1},
        "minimum_rules_by_source": {},
        "anomaly": {"absolute_delta": 1000, "percentage_delta": 5.0},
        "policy_exceptions": [],
    }
    with pytest.raises(SecurityGateError) as caught:
        run_gates(current, previous, policy, {"openai.com"}, PublicSuffixes.load(psl_path), {})
    assert caught.value.key == "anomaly.delta"

