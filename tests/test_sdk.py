"""
Unit Tests for AgentShield SDK / Middleware Interface
"""

import pytest
from agentshield_sdk import (
    AgentShield,
    AgentShieldSecurityException,
    AgentShieldApprovalRequiredException,
)


def test_sdk_blocks_unauthorized_tool():
    """Verify SDK check blocks disallowed tool and records audit event."""
    shield = AgentShield(mode="strict")
    result = shield.check(action="run_shell", payload="rm -rf /")
    assert result.decision == "BLOCK"
    assert len(shield.get_audit_trail()) == 1
    assert shield.verify_integrity()[0] is True


def test_sdk_protect_tool_decorator_block():
    """Verify @protect_tool raises AgentShieldSecurityException on prohibited action."""
    shield = AgentShield()

    @shield.protect_tool("run_shell")
    def dangerous_tool(cmd):
        return f"Executing {cmd}"

    with pytest.raises(AgentShieldSecurityException) as exc_info:
        dangerous_tool("cat /etc/shadow")

    assert "BLOCKED" in str(exc_info.value)


def test_sdk_protect_tool_decorator_approval():
    """Verify @protect_tool pauses on approval-required actions."""
    shield = AgentShield()

    @shield.protect_tool("send_email")
    def email_tool(to, body):
        return f"Sent to {to}"

    with pytest.raises(AgentShieldApprovalRequiredException) as exc_info:
        email_tool(to="client@example.com", body="Hello client")

    assert "REQUIRES APPROVAL" in str(exc_info.value)


def test_sdk_protect_tool_decorator_allow():
    """Verify @protect_tool allows permitted safe actions to execute."""
    shield = AgentShield()

    @shield.protect_tool("search_docs")
    def docs_tool(query):
        return f"Results for {query}"

    output = docs_tool("How to reset password?")
    assert output == "Results for How to reset password?"
    assert shield.verify_integrity()[0] is True
