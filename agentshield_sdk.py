"""
AgentShield - AI-Agent Permission Firewall
AgentShield Python SDK / Middleware Interface (Prototype)
Tagline: Trust the Task. Verify Every Action.
ChakraVyuh CyberShield Hackathon | Team TRUSTGRID AI

This module implements the foundational SDK middleware described in the
'Next Engineering Stage' of the AgentShield Product Guide.
"""

from typing import Dict, Any, Optional, Callable
from policy_engine import evaluate_policy, PolicyEvaluationResult
from audit_logger import AuditLogger, GENESIS_HASH


class AgentShieldSecurityException(Exception):
    """Raised when an action is blocked by AgentShield policy."""
    pass


class AgentShieldApprovalRequiredException(Exception):
    """Raised when an action requires human approval before execution."""
    pass


class AgentShield:
    """
    Developer-facing SDK middleware to gate AI-agent tool invocations.
    
    Usage:
        shield = AgentShield(mode="strict")
        result = shield.check(action="send_email", payload="Hello", destination="test@example.com")
        if result.decision == "ALLOW":
            execute_tool(...)
    """

    def __init__(
        self,
        mode: str = "strict",
        auto_audit: bool = True,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.mode = mode
        self.auto_audit = auto_audit
        self.audit_logger = audit_logger or AuditLogger()

    def check(
        self,
        action: str,
        payload: Any = "",
        destination: str = "",
        is_approved: bool = False,
        untrusted_context: str = "",
        is_simulated: bool = False,
    ) -> PolicyEvaluationResult:
        """
        Evaluates a tool call through the policy engine and records audit event.
        """
        result = evaluate_policy(
            action=action,
            payload=payload,
            destination=destination,
            is_approved=is_approved,
            untrusted_context=untrusted_context,
            is_simulated=is_simulated,
        )

        if self.auto_audit:
            self.audit_logger.record_event(
                action=action,
                status=result.decision,
                reason=result.reason,
                risk=result.risk,
                payload=str(payload),
                scenario="SDK Middleware Call",
                destination=destination,
                event_type=f"SDK_{result.decision}",
                remediation=result.remediation,
                execution_status=result.execution_status,
                triggered_rule=result.triggered_rule,
                is_simulated=is_simulated,
            )

        return result

    def protect_tool(self, action_name: str, tool_func: Optional[Callable] = None) -> Callable:
        """
        Decorator or wrapper that automatically gates a tool function.
        Can be used as:
            @shield.protect_tool("send_email")
            def send_email(...): ...
        or:
            gated_tool = shield.protect_tool("send_email", raw_tool_func)
        """
        def decorator(fn: Callable) -> Callable:
            def wrapped(*args, **kwargs):
                payload_str = f"args={args}, kwargs={kwargs}"
                destination = kwargs.get("destination", kwargs.get("to", ""))
                result = self.check(action=action_name, payload=payload_str, destination=destination)

                if result.decision == "BLOCK":
                    raise AgentShieldSecurityException(
                        f"AgentShield BLOCKED tool '{action_name}': {result.reason} (Risk: {result.risk})"
                    )
                elif result.decision == "REQUIRE_APPROVAL":
                    raise AgentShieldApprovalRequiredException(
                        f"AgentShield REQUIRES APPROVAL for '{action_name}': {result.reason}"
                    )

                # ALLOW - execute real tool
                return fn(*args, **kwargs)

            return wrapped

        if tool_func is not None:
            return decorator(tool_func)
        return decorator

    def get_audit_trail(self):
        """Returns the logged audit events."""
        return self.audit_logger.events

    def verify_integrity(self):
        """Cryptographically verifies the audit log hash chain."""
        from audit_logger import verify_chain
        return verify_chain(self.audit_logger.events)
