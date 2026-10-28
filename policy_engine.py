"""
AgentShield - AI-Agent Permission Firewall
Core Policy Engine Module
Tagline: Trust the Task. Verify Every Action.
ChakraVyuh CyberShield Hackathon | Team TRUSTGRID AI
"""

import re
from typing import Dict, List, Any, Optional, Tuple


# ==========================================
# CONSTANTS & CONFIGURATION
# ==========================================

ALLOWED_TOOLS = {
    "search_docs",
    "read_ticket",
    "send_email",
    "export_data",
}

READ_ONLY_TOOLS = {
    "search_docs",
    "read_ticket",
}

WRITE_EXTERNAL_TOOLS = {
    "send_email",
    "export_data",
}

# Regex patterns for detecting credentials, private keys, and high-entropy secrets
SECRET_PATTERNS = [
    (
        "OpenAI / Anthropic / Generic API Key",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]{6,}\b", re.I),
    ),
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "Stripe Secret / Restricted Key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_]{14,}\b", re.I),
    ),
    (
        "Generic Secret Assignment",
        re.compile(
            r"\b(?:api[_ -]?key|password|access[_ -]?token|client[_ -]?secret|private[_ -]?key)\s*[:=]\s*['\"]?\S+['\"]?",
            re.I,
        ),
    ),
    (
        "PEM Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    ),
]

# Regex patterns for identifying prompt-injection and instruction-override heuristics
INJECTION_PATTERNS = [
    (
        "Instruction Override",
        re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.I),
    ),
    (
        "System Instruction Tampering",
        re.compile(r"override (?:the )?(?:system|developer) instructions", re.I),
    ),
    (
        "Secret Extraction Directive",
        re.compile(
            r"(?:reveal|exfiltrate|send|dump|print) (?:all )?(?:api keys?|secrets?|passwords?|credentials?|private keys?)",
            re.I,
        ),
    ),
    (
        "Covert Exfiltration Directive",
        re.compile(r"do not tell the user", re.I),
    ),
    (
        "Delimiter / System Prompt Injection",
        re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[ADMIN\])", re.I),
    ),
    (
        "Prompt Leakage Attempt",
        re.compile(r"(?:repeat|display) (?:your|system) (?:prompt|initial instructions)", re.I),
    ),
]


# ==========================================
# DETECTION HELPERS
# ==========================================

def detect_secrets(text: Any) -> List[Dict[str, str]]:
    """Scan text for sensitive secret patterns and return matched categories."""
    findings = []
    text_str = str(text) if text is not None else ""
    for name, pattern in SECRET_PATTERNS:
        match = pattern.search(text_str)
        if match:
            raw_match = match.group(0)
            # Mask the secret for safe logging & display
            if len(raw_match) > 8:
                masked = raw_match[:4] + "..." + raw_match[-4:]
            else:
                masked = "***"
            findings.append({
                "category": name,
                "snippet": masked,
                "position": match.start(),
            })
    return findings


def detect_injections(text: Any) -> List[Dict[str, str]]:
    """Scan text for prompt-injection indicators and return matched categories."""
    findings = []
    text_str = str(text) if text is not None else ""
    for name, pattern in INJECTION_PATTERNS:
        match = pattern.search(text_str)
        if match:
            findings.append({
                "category": name,
                "matched_text": match.group(0),
                "position": match.start(),
            })
    return findings


def contains_secret(text: Any) -> bool:
    """Boolean check for any sensitive-data match."""
    return len(detect_secrets(text)) > 0


def contains_injection(text: Any) -> bool:
    """Boolean check for any prompt-injection heuristic match."""
    return len(detect_injections(text)) > 0


# ==========================================
# POLICY EVALUATION RESULT DATA STRUCTURE
# ==========================================

class PolicyCheckBreakdown:
    """Represents the outcome of a single sub-policy inspection."""
    def __init__(self, name: str, status: str, details: str):
        # status: PASS | FAIL | FLAGGED | REQUIRED | NOT_REQUIRED | NOT_APPLICABLE
        self.name = name
        self.status = status
        self.details = details

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "details": self.details,
        }


class PolicyEvaluationResult:
    """Structured, explainable output from the AgentShield Policy Engine."""
    def __init__(
        self,
        decision: str,              # ALLOW | REQUIRE_APPROVAL | BLOCK
        risk: str,                  # LOW | MEDIUM | HIGH | CRITICAL
        reason: str,
        remediation: str,
        breakdown: List[PolicyCheckBreakdown],
        triggered_rule: str,
        execution_status: str,      # NOT EXECUTED | PENDING APPROVAL | EXECUTED (SIMULATED) | FLAGGED (READ ONLY)
        detected_secrets: Optional[List[Dict[str, str]]] = None,
        detected_injections: Optional[List[Dict[str, str]]] = None,
        is_simulated: bool = True,
    ):
        self.decision = decision
        self.risk = risk
        self.reason = reason
        self.remediation = remediation
        self.breakdown = breakdown
        self.triggered_rule = triggered_rule
        self.execution_status = execution_status
        self.detected_secrets = detected_secrets or []
        self.detected_injections = detected_injections or []
        self.is_simulated = is_simulated

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "risk": self.risk,
            "reason": self.reason,
            "remediation": self.remediation,
            "breakdown": [b.to_dict() for b in self.breakdown],
            "triggered_rule": self.triggered_rule,
            "execution_status": self.execution_status,
            "detected_secrets": self.detected_secrets,
            "detected_injections": self.detected_injections,
            "is_simulated": self.is_simulated,
        }


# ==========================================
# CORE EVALUATION FUNCTION
# ==========================================

def evaluate_policy(
    action: str,
    payload: Any,
    destination: str = "",
    is_approved: bool = False,
    untrusted_context: str = "",
    is_simulated: bool = True,
) -> PolicyEvaluationResult:
    """
    Evaluates a proposed agent tool action against configured security policies.
    Returns a comprehensive PolicyEvaluationResult with full step-by-step breakdown.
    """
    full_content = f"{payload}\n{destination}\n{untrusted_context}"
    outbound_content = f"{payload}\n{destination}"

    breakdown: List[PolicyCheckBreakdown] = []

    # 1. TOOL ALLOWLIST CHECK
    if action not in ALLOWED_TOOLS:
        breakdown.append(PolicyCheckBreakdown(
            name="Tool Allowlist Check",
            status="FAIL",
            details=f"Tool '{action}' is not in the explicit allowlist. Denied by default.",
        ))
        breakdown.append(PolicyCheckBreakdown(
            name="Destination Policy Check",
            status="NOT APPLICABLE",
            details="Skipped due to unapproved tool.",
        ))
        breakdown.append(PolicyCheckBreakdown(
            name="Sensitive-Data Inspection",
            status="NOT APPLICABLE",
            details="Skipped due to unapproved tool.",
        ))
        
        # Check if untrusted content had injection attempts
        injections = detect_injections(full_content)
        if injections:
            breakdown.append(PolicyCheckBreakdown(
                name="Prompt-Injection Inspection",
                status="FLAGGED",
                details=f"Detected {len(injections)} injection pattern(s) in payload.",
            ))
        else:
            breakdown.append(PolicyCheckBreakdown(
                name="Prompt-Injection Inspection",
                status="PASS",
                details="No prompt injection indicators detected.",
            ))

        breakdown.append(PolicyCheckBreakdown(
            name="Human Approval Requirement",
            status="NOT APPLICABLE",
            details="Cannot approve an unallowlisted tool.",
        ))

        return PolicyEvaluationResult(
            decision="BLOCK",
            risk="HIGH",
            reason=f"Unknown or unapproved tool '{action}'. Denied by default under zero-trust policy.",
            remediation="Do not invoke unapproved tools. Add tool to explicit allowlist only after architectural and security review.",
            breakdown=breakdown,
            triggered_rule="Default-Deny Tool Allowlist",
            execution_status="NOT EXECUTED (SIMULATION PROTECTED)" if is_simulated else "NOT EXECUTED",
            detected_secrets=[],
            detected_injections=injections,
            is_simulated=is_simulated,
        )

    # Tool is in allowlist
    breakdown.append(PolicyCheckBreakdown(
        name="Tool Allowlist Check",
        status="PASS",
        details=f"Tool '{action}' is permitted under active policy.",
    ))

    # 2. SENSITIVE-DATA INSPECTION
    secrets = detect_secrets(outbound_content)
    if action in WRITE_EXTERNAL_TOOLS:
        if secrets:
            categories = ", ".join(s["category"] for s in secrets)
            breakdown.append(PolicyCheckBreakdown(
                name="Destination Policy Check",
                status="FAIL",
                details=f"Cannot transmit sensitive credentials to destination '{destination or 'unspecified'}'.",
            ))
            breakdown.append(PolicyCheckBreakdown(
                name="Sensitive-Data Inspection",
                status="FAIL",
                details=f"Outbound content matches prohibited credential pattern(s): {categories}.",
            ))
            breakdown.append(PolicyCheckBreakdown(
                name="Prompt-Injection Inspection",
                status="FLAGGED" if contains_injection(full_content) else "PASS",
                details="Checked content for adversarial instruction patterns.",
            ))
            breakdown.append(PolicyCheckBreakdown(
                name="Human Approval Requirement",
                status="NOT APPLICABLE",
                details="Hard security block takes precedence over manual approval.",
            ))

            return PolicyEvaluationResult(
                decision="BLOCK",
                risk="CRITICAL",
                reason=f"Outbound data payload contains detected sensitive credentials ({categories}). Execution prevented.",
                remediation="Sanitize payload, remove credential tokens, verify recipient address, and immediately rotate any exposed keys.",
                breakdown=breakdown,
                triggered_rule="Sensitive-Data Exfiltration Prevention",
                execution_status="NOT EXECUTED (SIMULATION PROTECTED)" if is_simulated else "NOT EXECUTED",
                detected_secrets=secrets,
                detected_injections=detect_injections(full_content),
                is_simulated=is_simulated,
            )
        else:
            breakdown.append(PolicyCheckBreakdown(
                name="Sensitive-Data Inspection",
                status="PASS",
                details="No sensitive credential or private key patterns detected in outbound payload.",
            ))
    else:
        # Read-only tools
        breakdown.append(PolicyCheckBreakdown(
            name="Sensitive-Data Inspection",
            status="NOT APPLICABLE",
            details="Read-only operation within internal boundary.",
        ))

    # 3. DESTINATION POLICY CHECK
    if action in WRITE_EXTERNAL_TOOLS:
        if destination:
            breakdown.append(PolicyCheckBreakdown(
                name="Destination Policy Check",
                status="PASS",
                details=f"Destination '{destination}' inspected.",
            ))
        else:
            breakdown.append(PolicyCheckBreakdown(
                name="Destination Policy Check",
                status="FAIL",
                details="External tool call missing required destination parameter.",
            ))
    else:
        breakdown.append(PolicyCheckBreakdown(
            name="Destination Policy Check",
            status="NOT APPLICABLE",
            details="Internal read-only resource access.",
        ))

    # 4. PROMPT-INJECTION / UNTRUSTED CONTENT INSPECTION
    injections = detect_injections(full_content)
    has_injection = len(injections) > 0

    if has_injection:
        categories = ", ".join(i["category"] for i in injections)
        breakdown.append(PolicyCheckBreakdown(
            name="Prompt-Injection Inspection",
            status="FLAGGED",
            details=f"Untrusted content contains suspicious prompt-injection indicator(s): {categories}.",
        ))
    else:
        breakdown.append(PolicyCheckBreakdown(
            name="Prompt-Injection Inspection",
            status="PASS",
            details="No prompt-injection or instruction-override patterns detected.",
        ))

    # For outbound actions, if payload contains injection directives, block immediately
    if action in WRITE_EXTERNAL_TOOLS and contains_injection(payload):
        breakdown.append(PolicyCheckBreakdown(
            name="Human Approval Requirement",
            status="NOT APPLICABLE",
            details="Hard block due to injection pattern in outbound action.",
        ))
        return PolicyEvaluationResult(
            decision="BLOCK",
            risk="HIGH",
            reason="The proposed outbound action contains an adversarial instruction-override pattern.",
            remediation="Discard embedded commands from untrusted sources; regenerate the response strictly from user's original task.",
            breakdown=breakdown,
            triggered_rule="Adversarial Injection Guard",
            execution_status="NOT EXECUTED (SIMULATION PROTECTED)" if is_simulated else "NOT EXECUTED",
            detected_secrets=secrets,
            detected_injections=injections,
            is_simulated=is_simulated,
        )

    # 5. READ-ONLY TOOL HANDLING
    if action in READ_ONLY_TOOLS:
        breakdown.append(PolicyCheckBreakdown(
            name="Human Approval Requirement",
            status="NOT REQUIRED",
            details="Read-only actions within safe data perimeter do not mandate human approval.",
        ))
        if has_injection:
            return PolicyEvaluationResult(
                decision="ALLOW",
                risk="MEDIUM",
                reason="Read-only access is permitted, but retrieved content contains a prompt-injection indicator. Content is quarantined as untrusted data.",
                remediation="Treat retrieved content strictly as raw untrusted data. Do not execute any embedded instructions in subsequent agent reasoning.",
                breakdown=breakdown,
                triggered_rule="Untrusted-Content Quarantine Heuristic",
                execution_status="EXECUTED (SIMULATED - READ ONLY QUARANTINED)" if is_simulated else "EXECUTED (READ ONLY)",
                detected_secrets=[],
                detected_injections=injections,
                is_simulated=is_simulated,
            )
        else:
            return PolicyEvaluationResult(
                decision="ALLOW",
                risk="LOW",
                reason="Read-only action complies with allowlist and safety policy. No security flags raised.",
                remediation="Proceed with standard task workflow.",
                breakdown=breakdown,
                triggered_rule="Permitted Read-Only Access",
                execution_status="EXECUTED (SIMULATED)" if is_simulated else "EXECUTED",
                detected_secrets=[],
                detected_injections=[],
                is_simulated=is_simulated,
            )

    # 6. EXTERNAL WRITE ACTIONS - HUMAN-IN-THE-LOOP APPROVAL CHECK
    if action in WRITE_EXTERNAL_TOOLS:
        if not is_approved:
            breakdown.append(PolicyCheckBreakdown(
                name="Human Approval Requirement",
                status="REQUIRED",
                details=f"Tool '{action}' performs external communication or data egress. Mandatory human approval required.",
            ))
            return PolicyEvaluationResult(
                decision="REQUIRE_APPROVAL",
                risk="HIGH",
                reason=f"External action '{action}' requires explicit human verification before execution under demo policy.",
                remediation="Review destination, payload content, and authorized context before approving execution.",
                breakdown=breakdown,
                triggered_rule="Human-in-the-Loop Gateway Requirement",
                execution_status="PENDING APPROVAL (EXECUTION HALTED)",
                detected_secrets=[],
                detected_injections=injections,
                is_simulated=is_simulated,
            )
        else:
            breakdown.append(PolicyCheckBreakdown(
                name="Human Approval Requirement",
                status="SATISFIED",
                details="Valid human operator approval signature recorded.",
            ))
            return PolicyEvaluationResult(
                decision="ALLOW",
                risk="LOW",
                reason="Human authorization confirmed. Outbound payload passed sensitive-data and allowlist checks.",
                remediation="Proceed with simulated safe execution through protected tool adapter.",
                breakdown=breakdown,
                triggered_rule="Human Authorization Verified",
                execution_status="EXECUTED (SIMULATED SAFE EXECUTION)" if is_simulated else "EXECUTED",
                detected_secrets=[],
                detected_injections=injections,
                is_simulated=is_simulated,
            )

    # Fallback default deny
    breakdown.append(PolicyCheckBreakdown(
        name="Fallback Safety Check",
        status="FAIL",
        details="No explicit policy matched.",
    ))
    return PolicyEvaluationResult(
        decision="BLOCK",
        risk="HIGH",
        reason="No matching allow rule found. Action denied under default-deny policy.",
        remediation="Review system policy configuration and tool parameters.",
        breakdown=breakdown,
        triggered_rule="Fallback Default-Deny",
        execution_status="NOT EXECUTED",
        detected_secrets=[],
        detected_injections=[],
        is_simulated=is_simulated,
    )


# ==========================================
# BACKWARD COMPATIBLE AUTHORIZE WRAPPER
# ==========================================

def authorize(
    action: str,
    payload: Any,
    approved: bool = False,
    destination: str = "",
) -> Tuple[str, str, str, str, List[Dict[str, str]]]:
    """
    Backward-compatible authorization wrapper returning:
    (status, reason, risk, remediation, breakdown_dicts)
    Status values: 'ALLOW', 'REQUIRE_APPROVAL', 'BLOCK', 'ALLOWED WITH WARNING'
    """
    result = evaluate_policy(
        action=action,
        payload=payload,
        destination=destination,
        is_approved=approved,
        is_simulated=True,
    )

    # Format status for backward compatibility
    if result.decision == "ALLOW" and result.detected_injections:
        status = "ALLOWED WITH WARNING"
    elif result.decision == "REQUIRE_APPROVAL":
        status = "REQUIRE APPROVAL"
    elif result.decision == "BLOCK":
        status = "BLOCKED"
    else:
        status = "ALLOWED"

    breakdown_list = [b.to_dict() for b in result.breakdown]
    return status, result.reason, result.risk, result.remediation, breakdown_list
