"""
Unit Tests for AgentShield Cryptographic Audit Logger & Hash Chain
"""

import pytest
from audit_logger import (
    AuditLogger,
    verify_chain,
    create_tampered_chain,
    canonical_json,
    compute_event_hash,
    GENESIS_HASH,
)


def test_audit_event_hash_deterministic():
    """Verify canonical json hashing is deterministic and reproducible."""
    data1 = {"b": 2, "a": 1, "c": [3, 4]}
    data2 = {"a": 1, "c": [3, 4], "b": 2}
    assert canonical_json(data1) == canonical_json(data2)
    assert compute_event_hash(data1) == compute_event_hash(data2)


def test_audit_logger_hash_chaining():
    """Verify events are sequentially chained to the previous event's hash."""
    logger = AuditLogger()
    assert logger.chain_hash == GENESIS_HASH

    ev1 = logger.record_event(
        action="search_docs",
        status="ALLOW",
        reason="Test reason 1",
        risk="LOW",
        payload="query: test",
    )
    assert ev1 is not None
    assert ev1["previous_hash"] == GENESIS_HASH
    assert ev1["hash"] != ""
    assert logger.chain_hash == ev1["hash"]

    ev2 = logger.record_event(
        action="send_email",
        status="BLOCK",
        reason="Test block 2",
        risk="CRITICAL",
        payload="secret payload",
    )
    assert ev2 is not None
    assert ev2["previous_hash"] == ev1["hash"]
    assert logger.chain_hash == ev2["hash"]

    # Verify whole chain
    is_valid, msg, f_idx = verify_chain(logger.events)
    assert is_valid is True
    assert f_idx == -1


def test_verify_chain_detects_tampered_payload():
    """Verify that tampering with an event's field breaks cryptographic verification."""
    logger = AuditLogger()
    for i in range(4):
        logger.record_event(
            action="search_docs",
            status="ALLOW",
            reason=f"Event {i}",
            risk="LOW",
            payload=f"Payload {i}",
        )

    # Valid initially
    assert verify_chain(logger.events)[0] is True

    # Tamper with event index 2
    tampered = create_tampered_chain(logger.events, target_index=2)
    is_valid, msg, f_idx = verify_chain(tampered)
    assert is_valid is False
    assert f_idx == 2
    assert "Cryptographic signature mismatch" in msg


def test_verify_chain_detects_severed_link():
    """Verify that altering previous_hash breaks link verification."""
    logger = AuditLogger()
    logger.record_event(action="tool1", status="ALLOW", reason="r1", risk="LOW", payload="p1")
    logger.record_event(action="tool2", status="ALLOW", reason="r2", risk="LOW", payload="p2")

    import copy
    broken = copy.deepcopy(logger.events)
    broken[1]["previous_hash"] = "FAKE_PREVIOUS_HASH_HEX"

    is_valid, msg, f_idx = verify_chain(broken)
    assert is_valid is False
    assert f_idx == 1
    assert "Hash link broken" in msg


def test_idempotency_prevents_duplicate_events():
    """Verify idempotency key stops duplicate audit events on Streamlit page reruns."""
    logger = AuditLogger()
    key = "action_nonce_12345"

    ev1 = logger.record_event(
        action="send_email",
        status="ALLOW",
        reason="First run",
        risk="LOW",
        payload="test",
        idempotency_key=key,
    )
    assert ev1 is not None
    assert len(logger.events) == 1

    # Rerun with identical key
    ev2 = logger.record_event(
        action="send_email",
        status="ALLOW",
        reason="Rerun duplicate",
        risk="LOW",
        payload="test",
        idempotency_key=key,
    )
    assert ev2 is None
    assert len(logger.events) == 1  # No duplicate added!
