"""
AgentShield — AI-Agent Permission Firewall
Tagline: Trust the Task. Verify Every Action.
ChakraVyuh CyberShield Hackathon | Team TRUSTGRID AI

Main Application Entrypoint
"""

import streamlit as st
import json
import re
from collections import Counter
from datetime import datetime, timezone

from policy_engine import (
    ALLOWED_TOOLS,
    evaluate_policy,
    authorize,
    detect_secrets,
    detect_injections,
    PolicyEvaluationResult,
)
from audit_logger import (
    AuditLogger,
    verify_chain,
    create_tampered_chain,
    GENESIS_HASH,
)
from approval_manager import ApprovalManager, ApprovalRequest
from scenarios import SCENARIOS
from agentshield_sdk import AgentShield


# ==========================================
# PAGE CONFIGURATION & THEME STYLING
# ==========================================

st.set_page_config(
    page_title="AgentShield | AI-Agent Permission Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Contrast Cybersecurity CSS
st.markdown("""
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #0B0F19;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Header Card */
    .shield-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }
    .shield-title {
        font-size: 26px;
        font-weight: 700;
        color: #F8FAFC;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .shield-tagline {
        font-size: 14px;
        color: #38BDF8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-top: 4px;
        margin-bottom: 8px;
    }
    .shield-meta {
        font-size: 13px;
        color: #94A3B8;
    }
    
    /* Metric Cards */
    .metric-card {
        background-color: #111827;
        border: 1px solid #1F2937;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .metric-val {
        font-size: 28px;
        font-weight: 700;
        margin: 4px 0;
    }
    .metric-lbl {
        font-size: 12px;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Badges & Status Pills */
    .badge-block {
        background-color: #7F1D1D;
        color: #FCA5A5;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        border: 1px solid #DC2626;
        display: inline-block;
    }
    .badge-approval {
        background-color: #78350F;
        color: #FDE68A;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        border: 1px solid #D97706;
        display: inline-block;
    }
    .badge-allow {
        background-color: #064E3B;
        color: #A7F3D0;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        border: 1px solid #059669;
        display: inline-block;
    }
    .badge-flagged {
        background-color: #7C2D12;
        color: #FDBA74;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        border: 1px solid #EA580C;
        display: inline-block;
    }
    
    /* Callouts & Alert Banners */
    .callout-box {
        background-color: #1E293B;
        border-left: 4px solid #38BDF8;
        padding: 12px 16px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 14px;
        font-size: 13px;
    }
    .callout-blocked {
        background-color: #1F1315;
        border-left: 4px solid #EF4444;
        padding: 14px 16px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 14px;
    }
    .callout-approval {
        background-color: #241A0E;
        border-left: 4px solid #F59E0B;
        padding: 14px 16px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 14px;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# CYBERSECURITY TABLE RENDERER (NO PANDAS)
# ==========================================

def render_cyber_table(records: list):
    """Renders a styled cybersecurity data table without importing or requiring pandas."""
    if not records:
        st.info("No records to display.")
        return

    headers = list(records[0].keys())
    th_items = "".join(
        f'<th style="padding: 10px 14px; border-bottom: 1px solid #334155; text-align: left; color: #94A3B8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px;">{h}</th>'
        for h in headers
    )

    row_items = []
    for r in records:
        tds = []
        for h in headers:
            val = str(r.get(h, ""))
            # Style badges automatically
            if val == "BLOCK":
                cell = "<span class='badge-block'>BLOCK</span>"
            elif val in {"REQUIRE_APPROVAL", "REQUIRE APPROVAL", "PENDING APPROVAL"}:
                cell = "<span class='badge-approval'>REQUIRE APPROVAL</span>"
            elif val in {"ALLOW", "ALLOWED"}:
                cell = "<span class='badge-allow'>ALLOW</span>"
            elif val in {"FLAGGED", "ALLOWED WITH WARNING"}:
                cell = "<span class='badge-flagged'>FLAGGED</span>"
            elif val in {"PASS", "SATISFIED"}:
                cell = "<span style='color: #10B981; font-weight: 700;'>PASS</span>"
            elif val == "FAIL":
                cell = "<span style='color: #EF4444; font-weight: 700;'>FAIL</span>"
            elif val == "REQUIRED":
                cell = "<span style='color: #F59E0B; font-weight: 700;'>REQUIRED</span>"
            elif val == "NOT APPLICABLE":
                cell = "<span style='color: #64748B;'>N/A</span>"
            elif val == "CRITICAL":
                cell = "<span style='color: #EF4444; font-weight: 700;'>CRITICAL</span>"
            elif val == "HIGH":
                cell = "<span style='color: #F97316; font-weight: 600;'>HIGH</span>"
            elif val == "MEDIUM":
                cell = "<span style='color: #FBBF24; font-weight: 600;'>MEDIUM</span>"
            elif val == "LOW":
                cell = "<span style='color: #34D399; font-weight: 600;'>LOW</span>"
            elif "..." in val or "evt_" in val or "appr_" in val:
                cell = f"<code style='color: #38BDF8;'>{val}</code>"
            else:
                cell = val
            tds.append(f'<td style="padding: 10px 14px; border-bottom: 1px solid #1E293B; font-size: 13px; color: #E2E8F0; vertical-align: middle;">{cell}</td>')
        row_items.append(f"<tr style='background-color: transparent;'>{''.join(tds)}</tr>")

    table_html = (
        f'<div style="overflow-x: auto; margin: 10px 0; border: 1px solid #1E293B; border-radius: 8px; background: #0F172A;">'
        f'<table style="width: 100%; border-collapse: collapse; text-align: left;">'
        f'<thead><tr style="background-color: #111827;">{th_items}</tr></thead>'
        f'<tbody>{"".join(row_items)}</tbody>'
        f'</table></div>'
    )
    st.markdown(table_html, unsafe_allow_html=True)


# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================

if "events" not in st.session_state:
    st.session_state.events = []
if "chain_hash" not in st.session_state:
    st.session_state.chain_hash = GENESIS_HASH
if "approvals" not in st.session_state:
    st.session_state.approvals = []
if "last_sim_result" not in st.session_state:
    st.session_state.last_sim_result = None
if "last_manual_result" not in st.session_state:
    st.session_state.last_manual_result = None
if "active_popup" not in st.session_state:
    st.session_state.active_popup = None
if "sim_history" not in st.session_state:
    st.session_state.sim_history = []
if "selected_event_id" not in st.session_state:
    st.session_state.selected_event_id = None
if "last_executed_action_key" not in st.session_state:
    st.session_state.last_executed_action_key = None

# Initialize manager wrappers around session state
audit_mgr = AuditLogger(events=st.session_state.events, chain_hash=st.session_state.chain_hash)
approval_mgr = ApprovalManager(requests=st.session_state.approvals)


# ==========================================
# DIALOG DEFINITIONS (STREAMLIT NATIVE MODALS)
# ==========================================

@st.dialog("🚨 THREAT BLOCKED", width="large")
def popup_threat_blocked(data: dict):
    st.markdown("""
    <div style="background-color: #2A0E11; border: 1px solid #DC2626; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <h4 style="color: #F87171; margin: 0 0 8px 0;">🛡️ Unauthorized Action Prevented by Policy Engine</h4>
        <p style="color: #FECACA; font-size: 13px; margin: 0;">
            The proposed agent tool call violated security policy rules and was intercepted before execution.
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"**Tool:** `{data.get('action')}`")
        st.markdown(f"**Decision:** <span class='badge-block'>BLOCK</span>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"**Risk Level:** `{data.get('risk')}`")
        st.markdown(f"**Triggered Policy:** `{data.get('triggered_rule')}`")
    with c3:
        st.markdown(f"**Execution Status:**")
        st.markdown("<span style='color: #EF4444; font-weight: 700;'>NOT EXECUTED</span>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(f"**Policy Explanation:**\n{data.get('reason')}")
    
    if data.get("detected_secrets"):
        st.markdown("**Detected Sensitive Patterns:**")
        for sec in data["detected_secrets"]:
            st.code(f"Category: {sec['category']} | Matched: {sec['snippet']}", language="text")

    if data.get("remediation"):
        st.info(f"**Recommended Remediation:** {data.get('remediation')}")

    st.caption("Mode: Simulated Sandbox Protection • Zero Real Tool Execution")

    b1, b2 = st.columns([1, 1])
    with b1:
        if st.button("🔍 View Incident in Event Center", key="btn_popup_view_event", type="primary", use_container_width=True):
            st.session_state.selected_event_id = data.get("event_id")
            st.session_state.active_popup = None
            st.rerun()
    with b2:
        if st.button("✕ Dismiss Alert", key="btn_popup_dismiss_block", use_container_width=True):
            st.session_state.active_popup = None
            st.rerun()


@st.dialog("⚠️ HUMAN APPROVAL REQUIRED", width="large")
def popup_approval_required(data: dict):
    req_id = data.get("approval_id")
    req = approval_mgr.get_by_id(req_id) if req_id else None

    st.markdown("""
    <div style="background-color: #2D1A08; border: 1px solid #D97706; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <h4 style="color: #FBBF24; margin: 0 0 8px 0;">✋ Action Gated: Explicit Authorization Required</h4>
        <p style="color: #FEF3C7; font-size: 13px; margin: 0;">
            This tool performs external communications or privileged operations. Human operator approval is mandated before tool invocation.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Requested Tool:** `{data.get('action')}`")
        st.markdown(f"**Destination:** `{data.get('destination') or 'None specified'}`")
        st.markdown(f"**Risk Assessment:** `{data.get('risk')}`")
    with col2:
        st.markdown(f"**Approval Request ID:** `{req_id}`")
        status_color = "#F59E0B" if (req and req.status == "PENDING") else ("#10B981" if req and req.status == "APPROVED" else "#EF4444")
        st.markdown(f"**Approval State:** <span style='color: {status_color}; font-weight: 700;'>{req.status if req else 'PENDING'}</span>", unsafe_allow_html=True)
        st.markdown(f"**Execution Status:** `{req.simulated_execution_status if req else 'PENDING'}`")

    st.markdown("---")
    st.markdown(f"**Proposed Payload:**")
    st.code(data.get("payload", "")[:400], language="text")
    st.markdown(f"**Reason for Review:** {data.get('reason')}")

    if req and req.status == "PENDING":
        st.warning("Tool execution remains paused. A rejected or pending action will NOT execute.")
        b_app, b_rej = st.columns(2)
        with b_app:
            if st.button("✅ Approve (Simulated Safe Execution)", type="primary", use_container_width=True, key=f"appr_btn_{req_id}"):
                success, msg, updated = approval_mgr.approve_request(req_id)
                if success:
                    st.session_state.approvals = approval_mgr.to_list()
                    audit_mgr.record_event(
                        action=updated.tool,
                        status="ALLOW",
                        reason=f"Human operator approved request {req_id}. Simulated safe execution completed.",
                        risk="LOW",
                        payload=updated.payload,
                        scenario=updated.scenario,
                        destination=updated.destination,
                        event_type="APPROVAL_GRANTED",
                        execution_status="EXECUTED (SIMULATED SAFE EXECUTION)",
                        triggered_rule="Operator Authorization Signed",
                        is_simulated=True,
                    )
                    st.session_state.events = audit_mgr.events
                    st.session_state.chain_hash = audit_mgr.chain_hash
                    st.toast("✅ Action approved. Simulated tool executed safely.", icon="🛡️")
                    st.session_state.active_popup = None
                    st.rerun()
        with b_rej:
            if st.button("🛑 Reject Action", use_container_width=True, key=f"rej_btn_{req_id}"):
                success, msg, updated = approval_mgr.reject_request(req_id)
                if success:
                    st.session_state.approvals = approval_mgr.to_list()
                    audit_mgr.record_event(
                        action=updated.tool,
                        status="BLOCK",
                        reason=f"Human operator rejected request {req_id}. Tool execution aborted.",
                        risk="HIGH",
                        payload=updated.payload,
                        scenario=updated.scenario,
                        destination=updated.destination,
                        event_type="APPROVAL_REJECTED",
                        execution_status="REJECTED - NOT EXECUTED",
                        triggered_rule="Operator Denial",
                        is_simulated=True,
                    )
                    st.session_state.events = audit_mgr.events
                    st.session_state.chain_hash = audit_mgr.chain_hash
                    st.toast("🛑 Action rejected. Execution permanently prevented.", icon="🚫")
                    st.session_state.active_popup = None
                    st.rerun()
    else:
        st.info(f"Result: {req.simulated_result if req else 'Resolved'}")
        if st.button("Close", key="btn_close_appr", use_container_width=True):
            st.session_state.active_popup = None
            st.rerun()


@st.dialog("🟠 SUSPICIOUS PROMPT-INJECTION DETECTED", width="large")
def popup_suspicious_injection(data: dict):
    st.markdown("""
    <div style="background-color: #2E1508; border: 1px solid #EA580C; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <h4 style="color: #FB923C; margin: 0 0 8px 0;">🔍 Untrusted Content Indicator Flagged</h4>
        <p style="color: #FFEDD5; font-size: 13px; margin: 0;">
            The AgentShield content scanner identified suspicious instruction-override patterns within incoming untrusted data.
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**Source:** `{data.get('scenario', 'Untrusted Inbound Data')}`")
        st.markdown(f"**Proposed Read Tool:** `{data.get('action')}`")
        st.markdown(f"**Policy Decision:** <span class='badge-flagged'>ALLOWED (QUARANTINED)</span>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"**Risk Tier:** `{data.get('risk')}`")
        st.markdown(f"**Triggered Check:** `{data.get('triggered_rule')}`")
        st.markdown(f"**Execution Status:** `READ ONLY (ISOLATED DATA)`")

    st.markdown("---")
    st.markdown("**Detected Adversarial Indicators:**")
    injections = data.get("detected_injections", [])
    if injections:
        for inj in injections:
            st.code(f"Pattern Category: {inj['category']}\nMatched Snippet: \"{inj['matched_text']}\"", language="text")
    else:
        st.code(data.get("reason"), language="text")

    st.markdown("""
    > [!IMPORTANT]
    > **Security Distinction:** Detecting suspicious text in untrusted content flags a potential threat, but does **not** mean an attack succeeded. 
    > Read-only inspection is permitted so the system can analyze the ticket, but any downstream actions attempting to follow injected commands will be strictly intercepted.
    """)

    st.info(f"**Recommended Mitigation:** {data.get('remediation')}")

    if st.button("✕ Dismiss Alert", key="btn_dismiss_inj", use_container_width=True):
        st.session_state.active_popup = None
        st.rerun()


@st.dialog("🚨 CRITICAL: AUDIT CHAIN INTEGRITY FAILURE", width="large")
def popup_integrity_failure(data: dict):
    st.markdown("""
    <div style="background-color: #360E12; border: 2px solid #EF4444; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <h3 style="color: #F87171; margin: 0 0 8px 0;">🚨 AUDIT LEDGER COMPROMISE DETECTED</h3>
        <p style="color: #FECACA; font-size: 14px; margin: 0;">
            Cryptographic verification detected an inconsistency in the SHA-256 hash chain!
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.error(data.get("message", "Integrity check failed."))
    st.markdown(f"**Failed Event Index:** `#{data.get('failed_index', -1)}`")
    st.markdown("""
    **Security Analysis:**
    The cryptographic hash of one or more audit events no longer matches its canonical payload, or the sequential previous_hash linkage was severed. 
    In a production system, this indicates unauthorized local file modification, database tampering, or event deletion.
    """)

    if st.button("Dismiss Critical Alert", use_container_width=True):
        st.session_state.active_popup = None
        st.rerun()


# Render any active popup dialog
if st.session_state.get("active_popup"):
    popup = st.session_state.active_popup
    p_type = popup.get("type")
    if p_type == "threat_blocked":
        popup_threat_blocked(popup)
    elif p_type == "approval_required":
        popup_approval_required(popup)
    elif p_type == "suspicious_injection":
        popup_suspicious_injection(popup)
    elif p_type == "integrity_failure":
        popup_integrity_failure(popup)


# ==========================================
# SIDEBAR NAVIGATION & STATUS
# ==========================================

with st.sidebar:
    st.markdown("### 🛡️ AgentShield")
    st.caption("ChakraVyuh CyberShield Hackathon 2026")
    st.caption("**Team:** TRUSTGRID AI")
    st.markdown("---")

    st.markdown("#### Active Defense Policies")
    st.success("🔒 Default-Deny for Unknown Tools")
    st.error("🛑 Sensitive-Data Exfiltration Block")
    st.warning("⚠️ Human-in-the-Loop for External Egress")
    st.info("🔍 Untrusted Content Heuristic Scanner")
    st.markdown("---")

    total_evals = len(st.session_state.events)
    total_blocks = sum(1 for e in st.session_state.events if e.get("status") == "BLOCK")
    pending_apprs = len(approval_mgr.get_pending())

    st.metric("Total Events Logged", total_evals)
    st.metric("Threats Intercepted", total_blocks)
    st.metric("Pending Approvals", pending_apprs)

    is_valid_chain, chain_msg, _ = verify_chain(st.session_state.events)
    if is_valid_chain:
        st.caption("🟢 **Ledger Integrity:** SHA-256 PASS")
    else:
        st.caption("🔴 **Ledger Integrity:** COMPROMISED")

    st.markdown("---")
    st.caption("📌 *In-Memory Session Storage: All audit logs and approval states are maintained securely in this session.*")


# ==========================================
# MAIN HEADER
# ==========================================

st.markdown("""
<div class="shield-header">
    <div class="shield-title">
        <span>🛡️</span> AGENTSHIELD — AI-AGENT PERMISSION FIREWALL
    </div>
    <div class="shield-tagline">Trust the Task. Verify Every Action.</div>
    <div class="shield-meta">
        <strong>ChakraVyuh CyberShield Hackathon</strong> • Developed by <strong>TRUSTGRID AI</strong> • Prototype v2.0
    </div>
</div>
""", unsafe_allow_html=True)


# ==========================================
# APPLICATION TABS
# ==========================================

tabs = st.tabs([
    "📊 Security Dashboard",
    "🧪 Attack Simulation Lab",
    "🚨 Security Event Center",
    "🔎 Manual Policy Check",
    "📜 Audit & Hash Chain",
    "🧭 Product & Local Integration",
    "ℹ️ How It Works",
])

tab_dash, tab_lab, tab_events, tab_manual, tab_audit, tab_product, tab_about = tabs


# ==============================================================================
# TAB 1: MAIN SECURITY DASHBOARD (REQUIREMENT 6)
# ==============================================================================
with tab_dash:
    st.subheader("Security Operations Command Center")
    st.caption("Real-time telemetry and firewall metrics computed directly from recorded event logs.")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-lbl">Actions Evaluated</div>
            <div class="metric-val" style="color: #38BDF8;">{len(st.session_state.events)}</div>
            <div style="font-size: 11px; color: #64748B;">Total tool calls checked</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        blocks_count = sum(1 for e in st.session_state.events if e.get("status") == "BLOCK")
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-lbl">Actions Blocked</div>
            <div class="metric-val" style="color: #EF4444;">{blocks_count}</div>
            <div style="font-size: 11px; color: #64748B;">Enforced threat blocks</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        pending_count = len(approval_mgr.get_pending())
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-lbl">Approvals Pending</div>
            <div class="metric-val" style="color: #F59E0B;">{pending_count}</div>
            <div style="font-size: 11px; color: #64748B;">Awaiting human authorization</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        sec_events_count = sum(
            1 for e in st.session_state.events 
            if e.get("status") in {"BLOCK", "REQUIRE_APPROVAL"} or e.get("event_type") in {"INJECTION_FLAGGED", "POLICY_BLOCK"}
        )
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-lbl">Security Incidents</div>
            <div class="metric-val" style="color: #F97316;">{sec_events_count}</div>
            <div style="font-size: 11px; color: #64748B;">Anomalies & Gated Actions</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_dist, col_health = st.columns([1, 1])

    with col_dist:
        st.markdown("#### Decision & Severity Breakdown")
        if st.session_state.events:
            decisions = [e.get("status", "UNKNOWN") for e in st.session_state.events]
            dec_counts = [{"Decision": k, "Count": v} for k, v in Counter(decisions).items()]

            risks = [e.get("risk", "LOW") for e in st.session_state.events]
            risk_counts = [{"Risk Tier": k, "Count": v} for k, v in Counter(risks).items()]

            c_sub1, c_sub2 = st.columns(2)
            with c_sub1:
                st.write("**Decisions:**")
                render_cyber_table(dec_counts)
            with c_sub2:
                st.write("**Risk Tiers:**")
                render_cyber_table(risk_counts)
        else:
            st.info("No policy evaluations recorded yet in this session. Run a simulation scenario or manual check below.")

    with col_health:
        st.markdown("#### Ledger Integrity & System State")
        is_intact, health_msg, failed_idx = verify_chain(st.session_state.events)
        if is_intact:
            st.success("🛡️ **Cryptographic Hash Chain:** INTACT & VALID")
            st.caption(f"{len(st.session_state.events)} events chained with SHA-256 digest linking back to GENESIS.")
        else:
            st.error(f"🚨 **Integrity Verification:** FAILED at event #{failed_idx}")
            st.caption(health_msg)

        st.markdown("""
        <div class="callout-box">
            <strong>Session-Local Storage Notice:</strong> Current metrics, approval states, and audit chains 
            are maintained in-memory for this evaluation session. No production persistence layer is connected.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### Recent Security Events")
    if st.session_state.events:
        recent = list(reversed(st.session_state.events))[:5]
        display_data = []
        for e in recent:
            display_data.append({
                "Timestamp (UTC)": e.get("time"),
                "Tool": e.get("action"),
                "Decision": e.get("status"),
                "Risk": e.get("risk"),
                "Execution Status": e.get("execution_status"),
                "Triggered Rule": e.get("triggered_rule"),
            })
        render_cyber_table(display_data)
    else:
        st.info("Clean state: No incidents recorded. Start by testing an attack in the Attack Simulation Lab.")


# ==============================================================================
# TAB 2: ATTACK SIMULATION LAB (REQUIREMENTS 4 & 5)
# ==============================================================================
with tab_lab:
    st.subheader("🧪 Attack Simulation Lab — Baseline vs. AgentShield")
    st.write(
        "Demonstrate real-time attack prevention by comparing an unprotected agent baseline against the "
        "AgentShield Policy Engine. The unprotected outcome is a simulated baseline showing the risk; the protected "
        "side runs the actual AgentShield policy inspection."
    )

    selected_scenario_name = st.selectbox(
        "Select Attack / Test Scenario:",
        list(SCENARIOS.keys()),
        index=0,
        key="scenario_selector",
    )
    sc = SCENARIOS[selected_scenario_name]

    sc_c1, sc_c2 = st.columns([1, 1])
    with sc_c1:
        st.markdown("#### 1. Original User Task")
        st.info(sc["user_task"])

        st.markdown("#### 2. Untrusted Inbound Content")
        st.text_area(
            "Untrusted content payload",
            sc["untrusted_content"],
            height=120,
            disabled=True,
            key="lab_untrusted_view",
        )

    with sc_c2:
        st.markdown("#### 3. Simulated Agent's Proposed Action")
        st.code(
            f"Tool: {sc['action']}\n"
            f"Destination: {sc['destination']}\n"
            f"Payload: {sc['payload']}",
            language="text",
        )
        st.markdown(f"**Security Category:** `{sc['category']}`")
        st.warning(f"**Threat Impact:** {sc['impact']}")

    st.markdown("<br>", unsafe_allow_html=True)
    run_sim = st.button("▶ Run Controlled Attack Simulation", type="primary", use_container_width=True)

    if run_sim:
        eval_result = evaluate_policy(
            action=sc["action"],
            payload=sc["payload"],
            destination=sc["destination"],
            is_approved=False,
            untrusted_context=sc["untrusted_content"],
            is_simulated=True,
        )

        ev = audit_mgr.record_event(
            action=sc["action"],
            status=eval_result.decision,
            reason=eval_result.reason,
            risk=eval_result.risk,
            payload=f"{sc['payload']} | dest={sc['destination']}",
            scenario=sc["name"],
            destination=sc["destination"],
            event_type=f"SIM_{eval_result.decision}",
            remediation=eval_result.remediation,
            execution_status=eval_result.execution_status,
            triggered_rule=eval_result.triggered_rule,
            is_simulated=True,
        )
        st.session_state.events = audit_mgr.events
        st.session_state.chain_hash = audit_mgr.chain_hash

        appr_id = None
        if eval_result.decision == "REQUIRE_APPROVAL":
            req_obj = approval_mgr.create_request(
                tool=sc["action"],
                action_summary=f"Dispatch {sc['action']} to {sc['destination']}",
                destination=sc["destination"],
                payload=sc["payload"],
                risk=eval_result.risk,
                reason=eval_result.reason,
                scenario=sc["name"],
            )
            st.session_state.approvals = approval_mgr.to_list()
            appr_id = req_obj.id

        st.session_state.last_sim_result = {
            "scenario": sc,
            "result": eval_result,
            "event": ev,
            "approval_id": appr_id,
        }

        if eval_result.decision == "BLOCK":
            st.session_state.active_popup = {
                "type": "threat_blocked",
                "action": sc["action"],
                "risk": eval_result.risk,
                "reason": eval_result.reason,
                "triggered_rule": eval_result.triggered_rule,
                "remediation": eval_result.remediation,
                "detected_secrets": eval_result.detected_secrets,
                "event_id": ev["id"] if ev else None,
            }
            st.rerun()
        elif eval_result.decision == "REQUIRE_APPROVAL":
            st.session_state.active_popup = {
                "type": "approval_required",
                "approval_id": appr_id,
                "action": sc["action"],
                "destination": sc["destination"],
                "risk": eval_result.risk,
                "reason": eval_result.reason,
                "payload": sc["payload"],
            }
            st.rerun()
        elif eval_result.decision == "ALLOW" and eval_result.detected_injections:
            st.session_state.active_popup = {
                "type": "suspicious_injection",
                "scenario": sc["name"],
                "action": sc["action"],
                "risk": eval_result.risk,
                "reason": eval_result.reason,
                "remediation": eval_result.remediation,
                "triggered_rule": eval_result.triggered_rule,
                "detected_injections": eval_result.detected_injections,
            }
            st.rerun()
        else:
            st.toast(f"✅ Action Allowed: '{sc['action']}' passed all security policies.", icon="🛡️")

    if st.session_state.last_sim_result:
        sim_res = st.session_state.last_sim_result
        sc_data = sim_res["scenario"]
        pol_res: PolicyEvaluationResult = sim_res["result"]
        ev_data = sim_res["event"]

        st.markdown("---")
        st.markdown("### 🔬 Simulation Result & Security Comparison")

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown(f"""
            <div style="background-color: #241113; border: 1px solid #7F1D1D; border-radius: 8px; padding: 16px;">
                <h4 style="color: #F87171; margin-top: 0;">🔴 WITHOUT AGENTSHIELD — SIMULATED BASELINE</h4>
                <div style="font-size: 18px; font-weight: 700; color: #EF4444; margin: 10px 0;">
                    {sc_data['baseline_outcome']}
                </div>
                <p style="color: #CBD5E1; font-size: 13px;">
                    {sc_data['baseline_note']}
                </p>
                <div style="font-size: 11px; color: #94A3B8; margin-top: 10px;">
                    <em>Hypothetical baseline: Illustrates consequences of an unconstrained AI agent without permission boundaries.</em>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_right:
            badge_class = (
                "badge-block" if pol_res.decision == "BLOCK"
                else ("badge-approval" if pol_res.decision == "REQUIRE_APPROVAL" else "badge-allow")
            )
            st.markdown(f"""
            <div style="background-color: #0F172A; border: 1px solid #334155; border-radius: 8px; padding: 16px;">
                <h4 style="color: #38BDF8; margin-top: 0;">🟢 WITH AGENTSHIELD — POLICY EVALUATION</h4>
                <div style="margin: 8px 0;">
                    <span class="{badge_class}">{pol_res.decision}</span>
                    <span style="margin-left: 8px; font-size: 13px; color: #94A3B8;">Risk: <strong>{pol_res.risk}</strong></span>
                </div>
                <div style="font-size: 13px; color: #E2E8F0; margin-top: 6px;">
                    <strong>Execution Status:</strong> <code>{pol_res.execution_status}</code>
                </div>
                <div style="font-size: 13px; color: #E2E8F0; margin-top: 4px;">
                    <strong>Triggered Policy:</strong> {pol_res.triggered_rule}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 📋 Explainable Policy Breakdown")
        st.caption("Each sub-policy evaluates deterministically. No check outcomes are fabricated.")

        breakdown_rows = []
        for b in pol_res.breakdown:
            breakdown_rows.append({
                "Policy Inspection": b.name,
                "Status": f"{b.status}",
                "Evaluation Details": b.details,
            })
        render_cyber_table(breakdown_rows)

        st.write(f"**Policy Rationale:** {pol_res.reason}")
        st.write(f"**Actionable Remediation:** {pol_res.remediation}")

        if pol_res.decision == "REQUIRE_APPROVAL" and sim_res.get("approval_id"):
            appr_req = approval_mgr.get_by_id(sim_res["approval_id"])
            if appr_req and appr_req.status == "PENDING":
                st.markdown("""
                <div class="callout-approval">
                    <strong>Human Authorization Required:</strong> This action is currently pending review. 
                    Approve or reject below to simulate the operator gate.
                </div>
                """, unsafe_allow_html=True)
                col_a1, col_a2 = st.columns(2)
                with col_a1:
                    if st.button("✅ Approve Action", key="lab_inline_approve", type="primary", use_container_width=True):
                        approval_mgr.approve_request(appr_req.id)
                        st.session_state.approvals = approval_mgr.to_list()
                        audit_mgr.record_event(
                            action=appr_req.tool,
                            status="ALLOW",
                            reason="Approved by operator in Attack Lab. Simulated tool completed safely.",
                            risk="LOW",
                            payload=appr_req.payload,
                            scenario=appr_req.scenario,
                            destination=appr_req.destination,
                            event_type="APPROVAL_GRANTED",
                            execution_status="EXECUTED (SIMULATED SAFE EXECUTION)",
                            triggered_rule="Operator Authorization Signed",
                            is_simulated=True,
                        )
                        st.session_state.events = audit_mgr.events
                        st.session_state.chain_hash = audit_mgr.chain_hash
                        st.toast("✅ Action approved. Simulated tool executed safely.", icon="🛡️")
                        st.rerun()
                with col_a2:
                    if st.button("🛑 Reject Action", key="lab_inline_reject", use_container_width=True):
                        approval_mgr.reject_request(appr_req.id)
                        st.session_state.approvals = approval_mgr.to_list()
                        audit_mgr.record_event(
                            action=appr_req.tool,
                            status="BLOCK",
                            reason="Rejected by operator in Attack Lab. Execution aborted.",
                            risk="HIGH",
                            payload=appr_req.payload,
                            scenario=appr_req.scenario,
                            destination=appr_req.destination,
                            event_type="APPROVAL_REJECTED",
                            execution_status="REJECTED - NOT EXECUTED",
                            triggered_rule="Operator Denial",
                            is_simulated=True,
                        )
                        st.session_state.events = audit_mgr.events
                        st.session_state.chain_hash = audit_mgr.chain_hash
                        st.toast("🛑 Action rejected. Execution permanently blocked.", icon="🚫")
                        st.rerun()
            elif appr_req:
                st.info(f"Approval Status: **{appr_req.status}** — {appr_req.simulated_result}")

        with st.expander("🔐 Cryptographic Audit Evidence & Hash Linkage"):
            if ev_data:
                st.code(
                    f"Event ID: {ev_data.get('id')}\n"
                    f"Previous Hash: {ev_data.get('previous_hash')}\n"
                    f"Current Hash:  {ev_data.get('hash')}",
                    language="text",
                )
                is_valid, msg, _ = verify_chain(st.session_state.events)
                st.write("**Ledger Integrity Status:**", "PASS ✅" if is_valid else "FAIL ❌")


# ==============================================================================
# TAB 3: SECURITY EVENT CENTER (REQUIREMENT 3)
# ==============================================================================
with tab_events:
    st.subheader("🚨 Security Event Center")
    st.caption("Centralized incident repository with full drill-down analysis, search, and filtering.")

    if not st.session_state.events:
        st.markdown("""
        <div style="text-align: center; padding: 48px 16px; background-color: #111827; border: 1px dashed #374151; border-radius: 8px;">
            <div style="font-size: 36px; margin-bottom: 8px;">🛡️</div>
            <h4 style="color: #94A3B8; margin-bottom: 4px;">No Security Events Recorded Yet</h4>
            <p style="color: #64748B; font-size: 13px; max-width: 480px; margin: 0 auto;">
                The event ledger is currently empty. Run an attack scenario in the <strong>Attack Simulation Lab</strong> 
                or test an action in <strong>Manual Policy Check</strong> to generate live events.
            </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        f_col1, f_col2, f_col3, f_col4 = st.columns([2, 1, 1, 1])
        with f_col1:
            search_query = st.text_input("🔍 Search Events (by tool, rule, reason, or ID):", key="event_search_box")
        with f_col2:
            severity_filter = st.selectbox("Severity:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="event_sev_filter")
        with f_col3:
            decision_filter = st.selectbox("Decision:", ["ALL", "BLOCK", "REQUIRE_APPROVAL", "ALLOW"], key="event_dec_filter")
        with f_col4:
            mode_filter = st.selectbox("Mode:", ["ALL", "Simulated", "Non-Simulated"], key="event_mode_filter")

        filtered_events = []
        for e in reversed(st.session_state.events):
            if search_query:
                q = search_query.lower()
                text_corpus = f"{e.get('id')} {e.get('action')} {e.get('reason')} {e.get('triggered_rule')} {e.get('scenario')} {e.get('payload')}".lower()
                if q not in text_corpus:
                    continue

            if severity_filter != "ALL" and e.get("risk") != severity_filter:
                continue

            if decision_filter != "ALL" and e.get("status") != decision_filter:
                continue

            if mode_filter == "Simulated" and not e.get("is_simulated", True):
                continue
            elif mode_filter == "Non-Simulated" and e.get("is_simulated", True):
                continue

            filtered_events.append(e)

        st.caption(f"Showing **{len(filtered_events)}** matching events (out of {len(st.session_state.events)} total).")

        event_options = {
            f"[{e.get('time')}] {e.get('action')} - {e.get('status')} ({e.get('risk')}) - ID: {e.get('id')}": e["id"]
            for e in filtered_events
        }

        default_index = 0
        if st.session_state.selected_event_id and st.session_state.selected_event_id in event_options.values():
            for idx, val in enumerate(event_options.values()):
                if val == st.session_state.selected_event_id:
                    default_index = idx
                    break

        selected_label = st.selectbox(
            "Select Event to Inspect in Detail:",
            list(event_options.keys()) if event_options else ["No matching events"],
            index=default_index if event_options else 0,
            key="event_drilldown_selector",
        )

        if event_options:
            selected_id = event_options[selected_label]
            target_event = next((e for e in st.session_state.events if e["id"] == selected_id), None)

            if target_event:
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown(f"### 📋 Incident Detail: `{target_event['id']}`")

                q1, q2 = st.columns(2)
                with q1:
                    st.markdown("#### 1. What Happened?")
                    st.write(f"Security event recorded during **{target_event.get('scenario', 'Unknown Context')}**.")
                    st.write(f"Policy Decision: **{target_event.get('status')}** (Risk Tier: **{target_event.get('risk')}**)")

                    st.markdown("#### 2. What Action Was Proposed?")
                    st.markdown(f"- **Tool Requested:** `{target_event.get('action')}`")
                    st.markdown(f"- **Target Destination:** `{target_event.get('destination') or 'None specified'}`")
                    st.markdown(f"- **Payload Preview:**")
                    st.code(target_event.get("payload", "")[:300], language="text")

                    st.markdown("#### 3. Which Rule Was Evaluated?")
                    st.write(f"Triggered Rule: **{target_event.get('triggered_rule', 'General Policy')}**")

                with q2:
                    st.markdown("#### 4. Why Was the Decision Made?")
                    st.write(f"**Policy Engine Rationale:** {target_event.get('reason')}")

                    st.markdown("#### 5. Did Execution Occur?")
                    exec_stat = target_event.get("execution_status", "NOT EXECUTED")
                    if "NOT EXECUTED" in exec_stat:
                        st.error(f"🛑 {exec_stat}")
                    elif "PENDING" in exec_stat:
                        st.warning(f"⚠️ {exec_stat}")
                    else:
                        st.success(f"🟢 {exec_stat}")

                    st.markdown("#### 6. What Should Happen Next?")
                    st.info(f"**Remediation Guidance:** {target_event.get('remediation')}")

                with st.expander("Cryptographic Signature & Integrity"):
                    st.markdown(f"**Event Hash:** `{target_event.get('hash')}`")
                    st.markdown(f"**Parent Link:** `{target_event.get('previous_hash')}`")
                    st.markdown(f"**Environment:** `{'Simulated Sandbox' if target_event.get('is_simulated', True) else 'Production Adapter'}`")

        st.markdown("---")
        st.markdown("#### All Filtered Events Ledger")
        table_records = []
        for e in filtered_events:
            table_records.append({
                "ID": e.get("id"),
                "Timestamp (UTC)": e.get("time"),
                "Tool": e.get("action"),
                "Decision": e.get("status"),
                "Risk": e.get("risk"),
                "Execution": e.get("execution_status"),
                "Rule": e.get("triggered_rule"),
                "Simulated": "Yes" if e.get("is_simulated", True) else "No",
            })
        render_cyber_table(table_records)


# ==============================================================================
# TAB 4: MANUAL POLICY CHECK (PRESERVED & ENHANCED)
# ==============================================================================
with tab_manual:
    st.subheader("🔎 Manual Policy Check")
    st.write("Submit ad-hoc tool requests to evaluate how the AgentShield policy engine responds.")

    m_left, m_right = st.columns(2)
    with m_left:
        m_action = st.selectbox(
            "Tool action",
            ["search_docs", "read_ticket", "send_email", "export_data", "run_shell", "delete_database"],
            key="m_action_input",
        )
        m_payload = st.text_area(
            "Payload / Content",
            "Customer update: Ticket #3928 is reviewed.",
            height=110,
            key="m_payload_input",
        )
        m_dest = st.text_input(
            "Destination (if applicable)",
            "customer@example.com",
            key="m_dest_input",
        )
        m_approved = st.checkbox(
            "Simulate Human Operator Approval Already Granted",
            key="m_appr_checkbox",
        )

        if st.button("Evaluate Request", type="primary", use_container_width=True, key="btn_eval_manual"):
            m_res = evaluate_policy(
                action=m_action,
                payload=m_payload,
                destination=m_dest,
                is_approved=m_approved,
                is_simulated=False,
            )

            m_ev = audit_mgr.record_event(
                action=m_action,
                status=m_res.decision,
                reason=m_res.reason,
                risk=m_res.risk,
                payload=f"{m_payload} | dest={m_dest}",
                scenario="Manual Policy Check",
                destination=m_dest,
                event_type=f"MANUAL_{m_res.decision}",
                remediation=m_res.remediation,
                execution_status=m_res.execution_status,
                triggered_rule=m_res.triggered_rule,
                is_simulated=False,
            )
            st.session_state.events = audit_mgr.events
            st.session_state.chain_hash = audit_mgr.chain_hash
            st.session_state.last_manual_result = (m_res, m_ev)

            if m_res.decision == "BLOCK":
                st.session_state.active_popup = {
                    "type": "threat_blocked",
                    "action": m_action,
                    "risk": m_res.risk,
                    "reason": m_res.reason,
                    "triggered_rule": m_res.triggered_rule,
                    "remediation": m_res.remediation,
                    "detected_secrets": m_res.detected_secrets,
                    "event_id": m_ev["id"] if m_ev else None,
                }
                st.rerun()
            elif m_res.decision == "REQUIRE_APPROVAL":
                appr_req = approval_mgr.create_request(
                    tool=m_action,
                    action_summary=f"Manual execution of {m_action}",
                    destination=m_dest,
                    payload=m_payload,
                    risk=m_res.risk,
                    reason=m_res.reason,
                    scenario="Manual Policy Check",
                )
                st.session_state.approvals = approval_mgr.to_list()
                st.session_state.active_popup = {
                    "type": "approval_required",
                    "approval_id": appr_req.id,
                    "action": m_action,
                    "destination": m_dest,
                    "risk": m_res.risk,
                    "reason": m_res.reason,
                    "payload": m_payload,
                }
                st.rerun()
            else:
                st.toast(f"✅ Action Allowed: '{m_action}' permitted by policy.", icon="🛡️")

    with m_right:
        if st.session_state.last_manual_result:
            m_res_obj, m_ev_obj = st.session_state.last_manual_result
            badge_class = (
                "badge-block" if m_res_obj.decision == "BLOCK"
                else ("badge-approval" if m_res_obj.decision == "REQUIRE_APPROVAL" else "badge-allow")
            )
            st.markdown(f"### Decision: <span class='{badge_class}'>{m_res_obj.decision}</span>", unsafe_allow_html=True)
            st.metric("Risk Tier", m_res_obj.risk)
            st.markdown(f"**Triggered Rule:** {m_res_obj.triggered_rule}")
            st.markdown(f"**Execution Status:** `{m_res_obj.execution_status}`")
            st.markdown(f"**Explanation:**\n{m_res_obj.reason}")
            st.markdown(f"**Suggested Remediation:**\n{m_res_obj.remediation}")
            if m_ev_obj:
                st.caption(f"Audit Hash: `{m_ev_obj.get('hash')[:24]}...`")
        else:
            st.info("Submit a manual check on the left to view the structured policy evaluation.")


# ==============================================================================
# TAB 5: AUDIT & HASH-CHAIN VERIFICATION (PRESERVED & ENHANCED)
# ==============================================================================
with tab_audit:
    st.subheader("📜 Cryptographic Audit Ledger & Tamper Verification")
    st.write(
        "Every decision evaluated by AgentShield is serialized canonically and cryptographically chained "
        "using SHA-256. This ensures tamper-evidence for post-incident security audits."
    )

    if st.session_state.events:
        a_col1, a_col2, a_col3 = st.columns([1, 1, 1])
        with a_col1:
            if st.button("🔐 Verify Hash-Chain Integrity", type="primary", use_container_width=True):
                is_valid, msg, f_idx = verify_chain(st.session_state.events)
                if is_valid:
                    st.success(f"Verification Successful: {msg}")
                else:
                    st.session_state.active_popup = {
                        "type": "integrity_failure",
                        "message": msg,
                        "failed_index": f_idx,
                    }
                    st.rerun()

        with a_col2:
            is_valid_now, _, _ = verify_chain(st.session_state.events)
            st.metric("Ledger Integrity", "PASS ✅" if is_valid_now else "TAMPERED ❌")

        with a_col3:
            st.download_button(
                "⬇️ Download Audit Ledger (JSON)",
                json.dumps(st.session_state.events, indent=2),
                file_name="agentshield_audit_ledger.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("🧪 Demonstration: Test Audit Tamper Detection"):
            st.caption(
                "Judges can safely test how the integrity check detects tampering. "
                "This runs a simulated check on a modified copy without corrupting your active session ledger."
            )
            if st.button("Simulate Tamper on Audit Copy"):
                tampered = create_tampered_chain(st.session_state.events, target_index=0)
                is_tamper_valid, t_msg, t_idx = verify_chain(tampered)
                if not is_tamper_valid:
                    st.session_state.active_popup = {
                        "type": "integrity_failure",
                        "message": f"SIMULATED TEST PASSED: {t_msg}",
                        "failed_index": t_idx,
                    }
                    st.rerun()

        st.markdown("#### Complete Sequential Audit Log")
        render_cyber_table(
            [
                {
                    "Time (UTC)": e["time"],
                    "Scenario": e["scenario"],
                    "Tool": e["action"],
                    "Decision": e["status"],
                    "Risk": e["risk"],
                    "Prev Hash": e["previous_hash"][:12] + "...",
                    "Event Hash": e["hash"][:12] + "...",
                }
                for e in reversed(st.session_state.events)
            ]
        )
    else:
        st.info("No audit events recorded yet. Run simulations or manual checks first.")

    st.markdown("---")
    st.markdown("#### Incident Response Operational Playbook")
    st.markdown("""
    1. **Contain:** Intercept and block unauthorized tool execution before the action contacts host resources or external APIs.
    2. **Investigate:** Inspect the Security Event Center for matching rules, untrusted content fragments, and recipient destinations.
    3. **Remediate:** Sanitize prompts, remove exposed credentials from context, and rotate credentials if transmission was attempted.
    4. **Verify:** Check SHA-256 audit ledger integrity to prove that logs were not modified post-incident.
    """)


# ==============================================================================
# TAB 6: PRODUCT & LOCAL INTEGRATION (REQUIREMENT 7)
# ==============================================================================
with tab_product:
    st.subheader("🧭 Product & Local Integration Roadmap")
    st.markdown(
        "AgentShield acts as a **permission and policy firewall between an AI agent and the tools it invokes**. "
        "The roadmap below separates what is currently implemented, the next engineering stage, and future capabilities."
    )

    p1, p2, p3 = st.tabs([
        "1. Current Prototype (Available Now)",
        "2. Next Engineering Stage (SDK Middleware)",
        "3. Future Enterprise Product",
    ])

    with p1:
        st.markdown("### 🧪 1. Current Prototype — Tested & Running")
        st.success("✅ Fully Functional in this Streamlit Application")
        st.markdown("""
        - **Streamlit Security Dashboard:** Real-time metrics computed directly from recorded event records.
        - **Rule-Based Policy Checks:** Explicit default-deny tool allowlist, multi-pattern credential regex matching, and prompt-injection heuristics.
        - **Controlled Attack Simulation Lab:** 6 reproducible scenarios demonstrating baseline risk vs. AgentShield protection.
        - **Real Approval State Machine:** State transitions across `PENDING`, `APPROVED`, and `REJECTED`, ensuring unapproved actions never execute.
        - **Cryptographic Audit Ledger:** Canonical JSON serialization and sequential SHA-256 hash chaining with tamper verification.
        - **Security Event Popups:** Automatic modals for blocked threats, approval gates, and injection warnings.
        """)
        st.warning("""
        **Prototype Limitations:** Operating in a secure simulated sandbox. It does not dispatch real external emails, 
        execute real shell commands, or interact with Antigravity directly. The audit log is maintained in session memory.
        """)

    with p2:
        st.markdown("### ⚙️ 2. Next Engineering Stage — Python SDK / Middleware")
        st.info("Architecture for direct integration into agentic runtimes (e.g., LangChain, LlamaIndex, Antigravity SDK).")

        st.code("""
AI Agent (LangChain / LlamaIndex / Custom Agent)
      |
      v
AgentShield SDK Middleware Wrapper
      |
      v
Policy Engine (Allowlist, Data Guard, Pattern & Semantic Scanners)
      |
      +---- ALLOW ------------> Safe Tool Adapter executes tool
      |
      +---- REQUIRE_APPROVAL -> Pause execution, enqueue human review
      |
      +---- BLOCK ------------> Deny execution, return security error
        """, language="text")

        st.markdown("#### Runnable Foundation Included in this Project:")
        st.write("A foundational `agentshield_sdk.py` module is included directly in this repository:")
        st.code("""from agentshield_sdk import AgentShield

shield = AgentShield(mode="strict")

# Gate any tool call programmatically:
result = shield.check(
    action="send_email",
    payload="Hello, your order is ready.",
    destination="customer@example.com",
    is_approved=False
)

if result.decision == "ALLOW":
    send_email(...)
elif result.decision == "REQUIRE_APPROVAL":
    pause_and_request_human_authorization(...)
else:  # BLOCK
    raise SecurityException("Execution blocked by AgentShield firewall.")
        """, language="python")

    with p3:
        st.markdown("### 🚀 3. Future Enterprise Product")
        st.markdown("""
        - **Local Policy Gateway Daemon:** Background service on `127.0.0.1:8765` intercepting agent tool traffic via reverse proxy.
        - **Persistent Immutable Ledger:** PostgreSQL / SQLite backed by cryptographic append-only signing and Cloud KMS.
        - **Multi-Channel Approval Workflows:** Real-time push notifications to Slack, Microsoft Teams, and mobile webhooks for human approval.
        - **Scoped Browser Integration:** Dedicated browser extension to gate web-based agent navigation, preventing unauthorized form submissions.
        - **Dynamic Web-Based Policy Manager:** Role-Based Access Control (RBAC) allowing security teams to update tool permissions dynamically.
        """)
        st.caption("Note: Separate external dashboards cannot automatically intercept arbitrary local desktop processes without explicit SDK routing hooks.")


# ==============================================================================
# TAB 7: HOW IT WORKS & ARCHITECTURE
# ==============================================================================
with tab_about:
    st.subheader("ℹ️ System Architecture & Principles")
    st.markdown("""
    AgentShield enforces **Zero-Trust Permission Boundaries** for Autonomous AI Agents.
    
    ### Core Principles
    1. **Default-Deny:** An AI agent cannot invoke any tool outside its explicitly configured allowlist.
    2. **Data-Loss Prevention (DLP):** Outbound communication and export payloads are continuously scanned for high-entropy secrets and credential patterns before dispatch.
    3. **Human-in-the-Loop Gating:** Privileged actions (external communications, bulk export, financial operations) pause execution until signed by a human operator.
    4. **Tamper-Evident Accountability:** Every policy evaluation produces a canonical, SHA-256 hash-chained audit record.
    5. **Prompt-Injection Quarantine:** Content containing adversarial injection directives is isolated as untrusted data, preventing the LLM from executing malicious commands.
    """)
    st.caption("TRUSTGRID AI • AgentShield • ChakraVyuh CyberShield Hackathon 2026")
