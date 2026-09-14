"""The example policies under examples/policies/ parse and follow their own tiering rules."""

from pathlib import Path

import pytest

from mcp_airlock import Policy

POLICIES = sorted((Path(__file__).resolve().parents[1] / "examples" / "policies").glob("*.yaml"))


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_example_policy(path: Path):
    policy = Policy.load(path)
    envs = {env for rule in policy.tools.values() for env in rule.tiers}
    assert envs & {"dev", "staging", "prod"}
    for env in envs & {"dev", "staging", "prod"}:
        assert Policy.load(path, env).environment == env

    tiers = {t for rule in policy.tools.values() for t in rule.tiers.values()}
    assert {"L0", "L2"} <= tiers, f"{path.name}: need at least one L0 and one L2 tool"

    for name, rule in policy.tools.items():
        writes = set(rule.tiers.values()) & {"L1", "L2", "L3"}
        if writes:
            assert rule.description, f"{path.name}: {name} is {writes} but has no description"
        if "L1" in writes:
            assert rule.count_arg or rule.description, f"{path.name}: {name} is L1 without rationale"
