"""
AgentShield - AI-Agent Permission Firewall
Audit Logger & Hash-Chain Verification Module
Tagline: Trust the Task. Verify Every Action.
ChakraVyuh CyberShield Hackathon | Team TRUSTGRID AI
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional


GENESIS_HASH = "GENESIS"


def canonical_json(data: Dict[str, Any]) -> str:
    """Serializes a dictionary into a canonical, deterministic JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_event_hash(raw_event: Dict[str, Any]) -> str:
    """Computes the SHA-256 hex digest of a canonical raw event dictionary."""
    serialized = canonical_json(raw_event)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditEvent:
    """Encapsulates a tamper-evident audit record."""
    def __init__(
        self,
        event_id: str,
        timestamp: str,
        scenario: str,
        event_type: str,
        action: str,
        destination: str,
        status: str,
        risk: str,
        reason: str,
        remediation: str,
        payload_preview: str,
        execution_status: str,
        triggered_rule: str,
        is_simulated: bool,
        previous_hash: str,
        event_hash: str = "",
    ):
        self.id = event_id
        self.time = timestamp
        self.scenario = scenario
        self.event_type = event_type
        self.action = action
        self.destination = destination
        self.status = status
        self.risk = risk
        self.reason = reason
        self.remediation = remediation
        self.payload = payload_preview[:1200]
        self.execution_status = execution_status
        self.triggered_rule = triggered_rule
        self.is_simulated = is_simulated
        self.previous_hash = previous_hash
        self.hash = event_hash or self.compute_hash()

    def get_hashable_dict(self) -> Dict[str, Any]:
        """Returns the dictionary containing all fields covered by the cryptographic signature."""
        return {
            "id": self.id,
            "time": self.time,
            "scenario": self.scenario,
            "event_type": self.event_type,
            "action": self.action,
            "destination": self.destination,
            "status": self.status,
            "risk": self.risk,
            "reason": self.reason,
            "remediation": self.remediation,
            "payload": self.payload,
            "execution_status": self.execution_status,
            "triggered_rule": self.triggered_rule,
            "is_simulated": self.is_simulated,
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        return compute_event_hash(self.get_hashable_dict())

    def to_dict(self) -> Dict[str, Any]:
        d = self.get_hashable_dict()
        d["hash"] = self.hash
        return d


class AuditLogger:
    """Manages an in-memory, tamper-evident SHA-256 hash-chained event ledger."""

    def __init__(self, events: Optional[List[Dict[str, Any]]] = None, chain_hash: str = GENESIS_HASH):
        self.events: List[Dict[str, Any]] = events if events is not None else []
        self.chain_hash: str = chain_hash
        # Cache of recently recorded event signatures to prevent rerun duplication
        self._processed_keys = set()

    def record_event(
        self,
        action: str,
        status: str,
        reason: str,
        risk: str,
        payload: Any,
        scenario: str = "Manual Policy Check",
        destination: str = "",
        event_type: str = "POLICY_DECISION",
        remediation: str = "Review audit trail and policy configuration.",
        execution_status: str = "NOT EXECUTED",
        triggered_rule: str = "General Policy",
        is_simulated: bool = True,
        idempotency_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Records a new audit event and updates the tamper-evident hash chain.
        Returns the created event dictionary, or None if skipped as duplicate.
        """
        # Prevent rerun duplicates if an idempotency key is supplied
        if idempotency_key:
            if idempotency_key in self._processed_keys:
                return None
            self._processed_keys.add(idempotency_key)

        event_id = f"evt_{uuid.uuid4().hex[:10]}"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prev_hash = self.chain_hash

        event_obj = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            scenario=scenario,
            event_type=event_type,
            action=action,
            destination=destination,
            status=status,
            risk=risk,
            reason=reason,
            remediation=remediation,
            payload_preview=str(payload),
            execution_status=execution_status,
            triggered_rule=triggered_rule,
            is_simulated=is_simulated,
            previous_hash=prev_hash,
        )

        event_dict = event_obj.to_dict()
        self.events.append(event_dict)
        self.chain_hash = event_dict["hash"]
        return event_dict


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, str, int]:
    """
    Verifies the integrity of a hash-chained event list.
    Returns:
        (is_valid: bool, detail_message: str, failed_index: int)
        failed_index is -1 if valid.
    """
    if not events:
        return True, "No events recorded; empty chain is trivially valid.", -1

    expected_previous = GENESIS_HASH

    for idx, e in enumerate(events):
        # 1. Check backward linkage
        if e.get("previous_hash") != expected_previous:
            return (
                False,
                f"Hash link broken at event #{idx} (ID: {e.get('id', 'unknown')}). "
                f"Expected previous_hash '{expected_previous[:12]}...', found '{str(e.get('previous_hash'))[:12]}...'",
                idx,
            )

        # 2. Extract hashable fields and recalculate SHA-256
        # Support both new rich events and original minimal format
        hashable_keys = (
            "id", "time", "scenario", "event_type", "action", "destination",
            "status", "risk", "reason", "remediation", "payload",
            "execution_status", "triggered_rule", "is_simulated", "previous_hash"
        )

        # Check if legacy format event
        if "id" not in e and "scenario" in e and "action" in e:
            raw = {k: e[k] for k in ("time", "scenario", "action", "status", "reason", "risk", "payload", "previous_hash") if k in e}
        else:
            raw = {k: e[k] for k in hashable_keys if k in e}

        computed = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()

        if computed != e.get("hash"):
            return (
                False,
                f"Cryptographic signature mismatch at event #{idx} (ID: {e.get('id', 'unknown')}). "
                f"Event content was altered after hash computation.",
                idx,
            )

        expected_previous = e.get("hash", "")

    return True, f"All {len(events)} events verified. Hash chain is intact and tamper-free.", -1


def create_tampered_chain(events: List[Dict[str, Any]], target_index: int = 0) -> List[Dict[str, Any]]:
    """
    Helper for security demonstrations and tests:
    Creates a deep copy of events where one event's payload has been modified,
    demonstrating how the integrity verification immediately catches tampering.
    """
    import copy
    tampered = copy.deepcopy(events)
    if tampered and 0 <= target_index < len(tampered):
        tampered[target_index]["reason"] = tampered[target_index]["reason"] + " [TAMPERED BY ATTACKER]"
    return tampered
