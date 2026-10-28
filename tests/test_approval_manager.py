"""
Unit Tests for AgentShield Human Approval State Machine
"""

import pytest
from approval_manager import ApprovalManager, ApprovalRequest


def test_approval_lifecycle_pending_to_approved():
    """Verify approval request creation, pending state, and transition to approved."""
    mgr = ApprovalManager()
    req = mgr.create_request(
        tool="send_email",
        action_summary="Outbound client update",
        destination="client@example.com",
        payload="Hello client",
        risk="HIGH",
        reason="External communication requires review",
        scenario="Test Scenario",
    )

    assert req.id.startswith("appr_")
    assert req.status == "PENDING"
    assert "NOT EXECUTED" in req.simulated_execution_status
    assert len(mgr.get_pending()) == 1

    # Transition to APPROVED
    success, msg, updated = mgr.approve_request(req.id, operator="Test Auditor")
    assert success is True
    assert updated.status == "APPROVED"
    assert updated.resolved_by == "Test Auditor"
    assert "EXECUTED" in updated.simulated_execution_status
    assert "SIMULATED EMAIL ADAPTER" in updated.simulated_result
    assert len(mgr.get_pending()) == 0


def test_approval_lifecycle_pending_to_rejected():
    """Verify approval rejection halts execution and prevents tool execution."""
    mgr = ApprovalManager()
    req = mgr.create_request(
        tool="export_data",
        action_summary="Dump database to cloud",
        destination="s3://bucket/",
        payload="dump data",
        risk="CRITICAL",
        reason="Data export review",
    )

    assert req.status == "PENDING"

    # Reject request
    success, msg, updated = mgr.reject_request(req.id, operator="Test Auditor", rejection_reason="Untrusted destination")
    assert success is True
    assert updated.status == "REJECTED"
    assert updated.simulated_execution_status == "REJECTED - NOT EXECUTED"
    assert "blocked" in updated.simulated_result.lower()
    assert len(mgr.get_pending()) == 0


def test_cannot_approve_already_resolved():
    """Verify state machine rejects transitions on non-pending requests."""
    mgr = ApprovalManager()
    req = mgr.create_request(
        tool="send_email",
        action_summary="Email",
        destination="test@example.com",
        payload="data",
        risk="HIGH",
        reason="Review",
    )

    mgr.approve_request(req.id)
    # Attempt second approval
    success, msg, _ = mgr.approve_request(req.id)
    assert success is False
    assert "already APPROVED" in msg
