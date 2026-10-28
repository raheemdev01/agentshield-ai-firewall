# 📝 AgentShield Changelog

All notable changes made to the AgentShield project for the **ChakraVyuh CyberShield Hackathon** upgrade are documented below.

---

## [Version 2.0.0] - ChakraVyuh Upgrade Release

### 1. Security Event Popups & Native Modals
- **Threat Blocked Modal (`@st.dialog`):** Added a prominent red alert modal that triggers automatically when an action is blocked. Displays the requested tool, risk tier (`CRITICAL`/`HIGH`), triggered policy name, explicit non-execution status (`NOT EXECUTED`), matched secret snippets, actionable remediation, and a one-click navigation button to view the incident in the Security Event Center.
- **Human Approval Modal:** Added an interactive amber modal for actions requiring human-in-the-loop authorization (`REQUIRE_APPROVAL`). Features real application state transitions (`PENDING`, `APPROVED`, `REJECTED`), live simulated safe tool adapter responses, and strict non-execution enforcement on rejected or pending actions.
- **Suspicious Prompt-Injection Modal:** Added an orange warning dialog highlighting detected adversarial instruction-override patterns within inbound untrusted content. Clearly distinguishes pattern detection from proof of attack compromise.
- **Action Allowed Toast (`st.toast`):** Replaced invasive full-screen alerts for permitted benign operations with compact, professional green toast notifications.
- **Audit Integrity Failure Modal:** Added a critical alert popup specifically displayed when cryptographic hash-chain verification fails.
- **Rerun Deduplication:** Implemented session-state tracking and idempotency keys to ensure that Streamlit page refreshes do not duplicate popups or repeat audit records.

### 2. Dedicated Security Event Center
- **Interactive SOC Incident Hub:** Created a dedicated, standalone tab for exploring recorded security telemetry.
- **Multi-Dimensional Filtering & Search:**
  - Full-text search across tools, rules, rationale, payloads, and incident IDs.
  - Dropdown filter by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Dropdown filter by Decision (`BLOCK`, `REQUIRE_APPROVAL`, `ALLOW`).
  - Filter by Mode (`Simulated Sandbox` vs. `Non-Simulated / Live`).
- **6-Point Incident Drill-Down Analysis:** Every selected event provides structured answers to:
  1. *What happened?*
  2. *What action was proposed?*
  3. *Which rule was evaluated?*
  4. *Why was the decision made?*
  5. *Did execution occur?*
  6. *What should happen next?*
- **Empty State:** Clean, professional placeholder display when no events are recorded.

### 3. Attack Simulation Lab Improvements
- **6 Reproducible Test Scenarios:**
  1. *Indirect prompt injection in customer email* (credential exfiltration attempt).
  2. *Synthetic API key exfiltration via data export* (DLP detection of AWS and Stripe keys).
  3. *Unknown tool invocation* (default-deny enforcement for bash shell execution).
  4. *External email action requiring human approval* (gating external communications).
  5. *Benign read-only request* (compliant documentation query).
  6. *Prompt injection in read-only content* (untrusted content quarantine).
- **Protected vs. Unprotected Comparison:** Side-by-side view contrasting an unconstrained baseline against the AgentShield policy evaluation.
- **Interactive Inline Approval:** Operator approval controls embedded directly into the simulation view for approval-gated scenarios.

### 4. Explainable Policy Engine
- **Modular Architecture:** Extracted policy logic into `policy_engine.py` with clean data structures (`PolicyCheckBreakdown`, `PolicyEvaluationResult`).
- **Step-by-Step Check Breakdown:**
  - Tool Allowlist Check (`PASS` / `FAIL`)
  - Destination Policy Check (`PASS` / `FAIL` / `NOT APPLICABLE`)
  - Sensitive-Data Inspection (`PASS` / `FAIL` / `NOT APPLICABLE`)
  - Prompt-Injection Inspection (`PASS` / `FLAGGED` / `NOT APPLICABLE`)
  - Human Approval Requirement (`REQUIRED` / `SATISFIED` / `NOT REQUIRED` / `NOT APPLICABLE`)
- **Expanded Pattern Coverage:** High-entropy regex matching for OpenAI keys, AWS Access Key IDs, Stripe restricted keys, generic secret assignments, and PEM private keys.
- **Zero-Trust Default Deny:** Guaranteed default denial for any tool outside the explicit allowlist.

### 5. Cryptographic Audit Ledger & Tamper Testing
- **Canonical Serialization:** Deterministic JSON formatting with sorted keys and compact separators.
- **Sequential SHA-256 Chaining:** Each record links cryptographically to the previous event's hash.
- **Tamper Demonstration Feature:** Added an interactive `Simulate Tamper on Audit Copy` tool allowing hackathon judges to verify how AgentShield instantly identifies tampered records without corrupting session logs.
- **JSON Ledger Export:** Full export capability for offline security analysis.

### 6. Foundational Python SDK Middleware
- **Runnable `agentshield_sdk.py`:** Shipped a concrete Python SDK wrapper implementing `AgentShield` class, `check()` method, `@protect_tool` decorators, and automated audit logging.

### 7. UI/UX & High-Contrast Design
- **Cybersecurity Dark Theme:** Custom CSS styling with charcoal/near-black backgrounds (`#0B0F19`), clean card borders (`#334155`), high-contrast typography, and standardized badge colorways (Red = Block, Amber = Approval, Orange = Flagged, Green = Allow).
- **Real Calculated Metrics:** Four real-time top-level metric counters calculated strictly from recorded session records with zero placeholder statistics.

### 8. Automated Verification Suite
- **30 Passing Pytest Unit Tests:** Validates policy engine decisions, audit chaining, tamper detection, approval state transitions, scenario outcomes, and SDK decorator functionality.
