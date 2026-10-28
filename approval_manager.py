"""
AgentShield - AI-Agent Permission Firewall
Human-in-the-Loop Approval State Machine
Tagline: Trust the Task. Verify Every Action.
ChakraVyuh CyberShield Hackathon | Team TRUSTGRID AI
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple


class ApprovalRequest:
    """Represents a gated action requiring human authorization."""
    def __init__(
        self,
        approval_id: str,
        created_at: str,
        tool: str,
        action_summary: str,
        destination: str,
        payload: str,
        risk: str,
        reason: str,
        status: str = "PENDING",  # PENDING | APPROVED | REJECTED
        scenario: str = "Attack Simulation Lab",
        resolved_at: Optional[str] = None,
        resolved_by: Optional[str] = None,
        simulated_execution_status: str = "NOT EXECUTED (AWAITING APPROVAL)",
        simulated_result: Optional[str] = None,
    ):
        self.id = approval_id
        self.created_at = created_at
        self.tool = tool
        self.action_summary = action_summary
        self.destination = destination
        self.payload = payload
        self.risk = risk
        self.reason = reason
        self.status = status
        self.scenario = scenario
        self.resolved_at = resolved_at
        self.resolved_by = resolved_by
        self.simulated_execution_status = simulated_execution_status
        self.simulated_result = simulated_result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "tool": self.tool,
            "action_summary": self.action_summary,
            "destination": self.destination,
            "payload": self.payload,
            "risk": self.risk,
            "reason": self.reason,
            "status": self.status,
            "scenario": self.scenario,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "simulated_execution_status": self.simulated_execution_status,
            "simulated_result": self.simulated_result,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        return cls(
            approval_id=data["id"],
            created_at=data["created_at"],
            tool=data["tool"],
            action_summary=data.get("action_summary", ""),
            destination=data.get("destination", ""),
            payload=data.get("payload", ""),
            risk=data.get("risk", "HIGH"),
            reason=data.get("reason", ""),
            status=data.get("status", "PENDING"),
            scenario=data.get("scenario", ""),
            resolved_at=data.get("resolved_at"),
            resolved_by=data.get("resolved_by"),
            simulated_execution_status=data.get("simulated_execution_status", "NOT EXECUTED"),
            simulated_result=data.get("simulated_result"),
        )


class ApprovalManager:
    """Manages application state transitions for human-in-the-loop approvals."""

    def __init__(self, requests: Optional[List[Dict[str, Any]]] = None):
        self.requests: Dict[str, ApprovalRequest] = {}
        if requests:
            for r in requests:
                req_obj = ApprovalRequest.from_dict(r)
                self.requests[req_obj.id] = req_obj

    def create_request(
        self,
        tool: str,
        action_summary: str,
        destination: str,
        payload: str,
        risk: str,
        reason: str,
        scenario: str = "Simulation",
    ) -> ApprovalRequest:
        """Creates and enqueues a new pending approval request."""
        approval_id = f"appr_{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        req = ApprovalRequest(
            approval_id=approval_id,
            created_at=timestamp,
            tool=tool,
            action_summary=action_summary,
            destination=destination,
            payload=payload,
            risk=risk,
            reason=reason,
            status="PENDING",
            scenario=scenario,
            simulated_execution_status="NOT EXECUTED (AWAITING APPROVAL)",
        )
        self.requests[approval_id] = req
        return req

    def approve_request(
        self,
        approval_id: str,
        operator: str = "Security Operator (ChakraVyuh Demo)",
    ) -> Tuple[bool, str, Optional[ApprovalRequest]]:
        """
        Transitions approval request to APPROVED.
        Executes a safe simulated tool action.
        NEVER makes real network calls or runs real commands.
        """
        req = self.requests.get(approval_id)
        if not req:
            return False, f"Approval request '{approval_id}' not found.", None

        if req.status != "PENDING":
            return False, f"Request '{approval_id}' is already {req.status}.", req

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        req.status = "APPROVED"
        req.resolved_at = timestamp
        req.resolved_by = operator
        req.simulated_execution_status = "EXECUTED (SIMULATED SAFE EXECUTION)"

        # Safe simulated adapter response
        if req.tool == "send_email":
            req.simulated_result = (
                f"[SIMULATED EMAIL ADAPTER] Email dispatched to '{req.destination}'. "
                f"Status: 200 OK (Simulated sandbox - no actual internet traffic generated)."
            )
        elif req.tool == "export_data":
            req.simulated_result = (
                f"[SIMULATED EXPORT ADAPTER] Data package safely exported to '{req.destination}'. "
                f"Status: Complete (Simulated sandbox - no real external writes)."
            )
        else:
            req.simulated_result = (
                f"[SIMULATED TOOL ADAPTER] Tool '{req.tool}' safely executed following operator approval."
            )

        return True, "Action approved. Simulated safe execution completed.", req

    def reject_request(
        self,
        approval_id: str,
        operator: str = "Security Operator (ChakraVyuh Demo)",
        rejection_reason: str = "Action denied by operator review.",
    ) -> Tuple[bool, str, Optional[ApprovalRequest]]:
        """
        Transitions approval request to REJECTED.
        Enforces strict non-execution.
        """
        req = self.requests.get(approval_id)
        if not req:
            return False, f"Approval request '{approval_id}' not found.", None

        if req.status != "PENDING":
            return False, f"Request '{approval_id}' is already {req.status}.", req

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        req.status = "REJECTED"
        req.resolved_at = timestamp
        req.resolved_by = operator
        req.simulated_execution_status = "REJECTED - NOT EXECUTED"
        req.simulated_result = f"Action rejected: {rejection_reason}. Tool execution was permanently blocked."

        return True, "Action rejected. Execution permanently halted.", req

    def get_pending(self) -> List[ApprovalRequest]:
        return [r for r in self.requests.values() if r.status == "PENDING"]

    def get_all(self) -> List[ApprovalRequest]:
        return list(self.requests.values())

    def get_by_id(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self.requests.get(approval_id)

    def to_list(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.requests.values()]
