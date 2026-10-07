"""policy.example.yaml: the descriptions an approver reads match what the proxy does."""

from pathlib import Path

from mcp_airlock import Policy

ROOT = Path(__file__).resolve().parents[1]


def test_restart_service_description_does_not_claim_l2_is_refused():
    # The description is shown in the L2 prompt. A tool without dry_run is refused at L1 only;
    # at L2 it is confirmed without a preview and then runs, so the text must not say otherwise.
    rule = Policy.load(ROOT / "policy.example.yaml", "prod").tools["restart_service"]
    assert rule.tiers["prod"] == "L2"
    assert "L1/L2" not in rule.description
    assert "refuses it at L1" in rule.description and "L2" in rule.description
