# 🛡️ AgentShield — AI-Agent Permission Firewall

> **Tagline:** Trust the Task. Verify Every Action.  
> **Team:** TRUSTGRID AI  
> **Event:** ChakraVyuh CyberShield Hackathon 2026  

---

## 📖 Executive Summary

**AgentShield** is an AI-agent security firewall designed to enforce zero-trust permission boundaries, prevent sensitive data exfiltration, isolate adversarial prompt injection, and mandate human-in-the-loop authorization before dangerous actions execute.

Traditional AI agents connect Large Language Models (LLMs) directly to external tools, APIs, and host shells. When an attacker delivers indirect prompt injection (e.g., via customer support emails, untrusted web documents, or vendor tickets), the unconstrained LLM can be coerced into exfiltrating credentials, executing unauthorized bash commands, or contacting external threat actors.

**AgentShield intercepts every proposed tool action at the runtime boundary, evaluating it against deterministic security policies and recording every decision in a cryptographically verifiable SHA-256 hash-chained audit ledger.**

---

## 🚀 Quickstart & Local Execution

### 1. Prerequisites
- Python 3.10 to 3.14
- Standard terminal (PowerShell, Bash, Command Prompt)

### 2. Installation
Clone or extract the repository, navigate into the project directory, and install the minimal dependencies:

```bash
python -m pip install -r requirements.txt
```

### 3. Run the Application
Launch the Streamlit security command center:

```bash
python -m streamlit run app.py
```

Streamlit will print the local URL (typically **http://localhost:8501**). Open it in your web browser.

---

## 🧪 Testing the Attack Simulation Lab & Security Popups

The application includes 6 reproducible, deterministic scenarios demonstrating baseline vulnerability vs. AgentShield protection:

1. **Navigate to the `🧪 Attack Simulation Lab` tab.**
2. **Select an Attack / Test Scenario** from the dropdown:
   - `1. Indirect prompt injection in customer email`: Tests credential theft and external exfiltration via injected email.
   - `2. Synthetic API key exfiltration via data export`: Tests detection of synthetic AWS and Stripe secrets in outbound telemetry dump.
   - `3. Unknown tool invocation (shell execution)`: Tests default-deny policy when an agent attempts to invoke unapproved tools (`run_shell`).
   - `4. External email action requiring human approval`: Tests human-in-the-loop gating for benign outbound customer communications.
   - `5. Benign read-only request (allow)`: Tests compliant read-only knowledge base query (`search_docs`).
   - `6. Prompt injection in read-only content (quarantined)`: Tests untrusted content heuristic scanner and warning quarantine.
3. **Click `▶ Run Controlled Attack Simulation`**:
   - **Threat Blocked Modal (`🚨 THREAT BLOCKED`):** Appears automatically for Scenarios 1, 2, and 3. Displays tool name, CRITICAL/HIGH risk tier, triggered policy, non-execution confirmation, and a button to view the incident in the Event Center.
   - **Human Approval Modal (`⚠️ HUMAN APPROVAL REQUIRED`):** Appears for Scenario 4. Features interactive **`Approve`** and **`Reject`** controls with real application state transitions (`PENDING` ➔ `APPROVED` / `REJECTED`).
   - **Prompt-Injection Warning Modal (`🟠 SUSPICIOUS PROMPT-INJECTION DETECTED`):** Appears for Scenario 6. Explicitly distinguishes suspicious text detection from proof of attack success.
   - **Action Allowed Toast:** Emits a compact green toast notification (`st.toast`) for Scenario 5 without noisy dialogs.

---

## 🚨 Security Event Center & Drill-Down Analysis

Access the **`🚨 Security Event Center`** tab to explore real recorded security telemetry:
- **Search:** Query events by tool name, rule, reason, payload, or event ID.
- **Filters:** Multi-dimensional filtering by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), Decision (`BLOCK`, `REQUIRE_APPROVAL`, `ALLOW`), and Mode (`Simulated` vs. `Non-Simulated`).
- **Incident Drill-Down:** Selecting any incident answers the 6 critical SOC investigation questions:
  1. *What happened?*
  2. *What action was proposed?*
  3. *Which rule was evaluated?*
  4. *Why was the decision made?*
  5. *Did execution occur?* (Explicitly verifying non-execution for blocked/pending actions).
  6. *What should happen next?* (Incident response remediation guidance).

---

## 📜 Cryptographic Audit Ledger & Tamper Verification

Every decision evaluated by AgentShield is serialized into canonical JSON and cryptographically linked using SHA-256 digests back to `GENESIS`.

1. **Verify Hash Chain:** Click **`🔐 Verify Hash-Chain Integrity`** in the `📜 Audit & Hash Chain` tab to mathematically verify sequential linkage.
2. **Test Tamper Detection:** Open the **`🧪 Demonstration: Test Audit Tamper Detection`** expander and click **`Simulate Tamper on Audit Copy`**. AgentShield immediately detects the corrupted signature, identifies the exact tampered event index, and displays a critical integrity alert.
3. **Export:** Download the full immutable audit trail as a formatted JSON report.

---

## 🧩 Foundational Python SDK (`agentshield_sdk.py`)

In addition to the interactive dashboard, this project includes a runnable, importable Python SDK wrapper representing the **Next Engineering Stage**:

```python
from agentshield_sdk import AgentShield, AgentShieldSecurityException, AgentShieldApprovalRequiredException

shield = AgentShield(mode="strict")

# Option 1: Direct policy check
result = shield.check(
    action="send_email",
    payload="Hello, your order has shipped.",
    destination="customer@acme.com",
    is_approved=False
)

if result.decision == "ALLOW":
    send_email(...)
elif result.decision == "REQUIRE_APPROVAL":
    pause_for_human_review(...)
else:  # BLOCK
    raise AgentShieldSecurityException("Action blocked by firewall.")

# Option 2: Decorator wrapper for tool functions
@shield.protect_tool("send_email")
def dispatch_email(to, body):
    # This function is automatically intercepted before invocation
    return real_email_client.send(to=to, body=body)
```

---

## 🧪 Running Automated Unit Tests

A comprehensive suite of 30 unit tests verifies policy logic, regex patterns, audit hash integrity, approval states, and SDK decorators:

```bash
python -m pytest tests/ -v
```

### Test Coverage Highlights:
- **`tests/test_policy_engine.py`**: Default-deny allowlisting, sensitive credential detection (OpenAI keys, AWS credentials, Stripe keys, PEM blocks), prompt-injection patterns, human approval gating, and explainable check breakdowns.
- **`tests/test_audit_logger.py`**: Canonical JSON serialization, sequential SHA-256 chaining, tamper detection, severed link detection, and rerun idempotency.
- **`tests/test_approval_manager.py`**: State transitions (`PENDING` ➔ `APPROVED` / `REJECTED`), non-execution enforcement, and simulated adapter responses.
- **`tests/test_scenarios.py`**: Deterministic verification of all 6 attack and benign scenarios.
- **`tests/test_sdk.py`**: SDK check operations, `@protect_tool` decorator exception handling, and audit verification.

---

## 📂 Project Architecture

```
agentshield/
├── app.py                  # Main Streamlit web application & UI navigation
├── policy_engine.py         # Deterministic zero-trust policy engine & explainable checks
├── audit_logger.py          # Canonical serialization & SHA-256 hash-chain ledger
├── approval_manager.py      # Human-in-the-loop state machine (PENDING, APPROVED, REJECTED)
├── scenarios.py             # Reproducible attack lab scenarios & baseline comparisons
├── agentshield_sdk.py       # Importable Python SDK middleware foundation
├── requirements.txt         # Minimal production dependencies (Streamlit & Pytest)
├── README.md                # Comprehensive documentation & execution guide
├── CHANGELOG.md             # Detailed release & upgrade changelog
└── tests/                   # Automated pytest suite (30 passing tests)
    ├── test_policy_engine.py
    ├── test_audit_logger.py
    ├── test_approval_manager.py
    ├── test_scenarios.py
    └── test_sdk.py
```

---

## 🔒 Important Security Limitations & Prototype Context

- **Controlled Demo Environment:** Tool actions are simulated. The prototype does not transmit real emails, execute live bash scripts, or alter local disk files.
- **Synthetic Test Data:** Demonstrations utilize synthetic credentials (e.g., `sk_test_AgentShield_DEMO123`, `AKIAIOSFODNN7EXAMPLE`). Never input live production keys.
- **Session-Local Ledger:** In the current prototype, the hash-chained audit ledger resides in Streamlit session memory. Production deployments require persistent append-only database storage (e.g., KMS-signed SQLite or PostgreSQL).
- **Prompt-Injection Defense:** Pattern matching and heuristic analysis provide crucial defense-in-depth, but no system can guarantee 100% universal prompt-injection immunity without strong tool-level authorization boundaries.

---

**Developed by TRUSTGRID AI for the ChakraVyuh CyberShield Hackathon 2026.**  
*Trust the Task. Verify Every Action.*
