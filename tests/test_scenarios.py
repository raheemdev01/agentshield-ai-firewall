"""
Unit Tests for Reproducible Attack Lab Scenarios
"""

import pytest
from scenarios import SCENARIOS
from policy_engine import evaluate_policy


@pytest.mark.parametrize("scenario_key", list(SCENARIOS.keys()))
def test_all_scenarios_deterministic_outcome(scenario_key):
    """
    Verify each of the reproducible attack scenarios evaluates to its
    expected decision, risk tier, and triggered policy rule.
    """
    sc = SCENARIOS[scenario_key]
    result = evaluate_policy(
        action=sc["action"],
        payload=sc["payload"],
        destination=sc["destination"],
        is_approved=False,
        untrusted_context=sc["untrusted_content"],
        is_simulated=True,
    )

    assert result.decision == sc["expected_decision"], f"Scenario '{sc['name']}' decision mismatch"
    assert result.risk == sc["expected_risk"], f"Scenario '{sc['name']}' risk mismatch"
    assert result.triggered_rule == sc["triggered_rule"], f"Scenario '{sc['name']}' rule mismatch"
