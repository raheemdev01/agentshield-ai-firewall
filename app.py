import streamlit as st
import hashlib, json, re
from datetime import datetime, timezone

st.set_page_config(page_title="AgentShield | Security Console", page_icon="🛡️", layout="wide")

if "events" not in st.session_state:
    st.session_state.events = []
if "chain_hash" not in st.session_state:
    st.session_state.chain_hash = "GENESIS"

def record(action, status, reason, risk, payload):
    previous = st.session_state.chain_hash
    event = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": action, "status": status, "reason": reason, "risk": risk,
        "payload": payload, "previous_hash": previous
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    event_hash = hashlib.sha256(canonical.encode()).hexdigest()
    event["hash"] = event_hash
    st.session_state.events.append(event)
    st.session_state.chain_hash = event_hash

def authorize(action, payload, approved=False):
    text = str(payload).lower()
    # Demo-only policies. In a real system, authorization must be enforced at the tool adapter.
    if action not in {"search_docs", "read_ticket", "send_email", "export_data"}:
        return "BLOCKED", "Unknown tool: deny by default", "HIGH"
    if action == "search_docs":
        return "ALLOWED", "Read-only search is permitted", "LOW"
    if action == "read_ticket":
        return "ALLOWED", "Ticket read is permitted; returned content remains untrusted", "LOW"
    if action == "send_email":
        sensitive = bool(re.search(r"(password|api[_ -]?key|secret|token|private key)", text))
        if sensitive:
            return "BLOCKED", "Sensitive-data pattern detected in outgoing content", "CRITICAL"
        if not approved:
            return "APPROVAL REQUIRED", "External communication needs explicit human approval", "HIGH"
        return "ALLOWED", "Human approved the external action", "HIGH"
    if action == "export_data":
        if not approved:
            return "APPROVAL REQUIRED", "Data export requires explicit human approval", "HIGH"
        return "ALLOWED", "Human approved the export", "HIGH"

st.title("🛡️ AgentShield")
st.caption("Prototype security console • Policy checks before simulated tool execution")
st.warning("Demo mode: all tools are simulated. This prototype demonstrates policy decisions; it is not a production security boundary.")

with st.sidebar:
    st.header("Policy status")
    st.success("Default deny for unknown tools")
    st.info("Sensitive outbound data blocked")
    st.info("External actions require approval")
    st.caption("Audit log uses a SHA-256 hash chain for tamper-evidence, not a guarantee of immutability.")

left, right = st.columns([1, 1])
with left:
    st.subheader("1. Request an agent action")
    action = st.selectbox("Tool action", ["search_docs", "read_ticket", "send_email", "export_data", "run_shell"])
    if action == "search_docs":
        payload = st.text_input("Search query", "latest project status")
    elif action == "read_ticket":
        payload = st.text_area("Ticket / retrieved content", "Customer asks for a refund status.")
    elif action == "send_email":
        payload = st.text_area("Email body / outbound content", "Hello, your request is being reviewed.")
    elif action == "export_data":
        payload = st.text_area("Export description", "Export approved summary report.")
    else:
        payload = st.text_input("Command / payload", "cat ~/.ssh/id_rsa")
    approved = st.checkbox("Human approval granted for this request")
    if st.button("Evaluate request", type="primary", use_container_width=True):
        status, reason, risk = authorize(action, payload, approved)
        record(action, status, reason, risk, payload)
        st.session_state.last_result = (status, reason, risk)

with right:
    st.subheader("2. Firewall decision")
    result = st.session_state.get("last_result")
    if result:
        status, reason, risk = result
        if status == "ALLOWED":
            st.success(f"Decision: {status}")
        elif status == "BLOCKED":
            st.error(f"Decision: {status}")
        else:
            st.warning(f"Decision: {status}")
        st.metric("Risk tier", risk)
        st.write(reason)
    else:
        st.write("Submit an action to see the policy decision.")
    st.markdown("**Try these test cases**")
    st.markdown("- `send_email` with `My API key is sk_test_secret` → blocked")
    st.markdown("- `send_email` with ordinary text and no approval → approval required")
    st.markdown("- `run_shell` → blocked (unknown tool)")
    st.markdown("- `search_docs` → allowed")

st.divider()
st.subheader("3. Tamper-evident decision log")
events = st.session_state.events
if events:
    st.dataframe([
        {k: e[k] for k in ("time", "action", "status", "risk", "reason", "previous_hash", "hash")}
        for e in reversed(events)
    ], use_container_width=True, hide_index=True)
    if st.button("Verify current hash chain"):
        valid = True
        previous = "GENESIS"
        for e in events:
            if e["previous_hash"] != previous:
                valid = False
                break
            raw = {k: e[k] for k in ("time", "action", "status", "reason", "risk", "payload", "previous_hash")}
            expected = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if expected != e["hash"]:
                valid = False
                break
            previous = e["hash"]
        if valid:
            st.success("Hash-chain integrity check passed for current session.")
        else:
            st.error("Hash-chain integrity check failed.")
    st.download_button("Download audit log (JSON)", json.dumps(events, indent=2), file_name="agentshield_audit.json")
else:
    st.caption("No actions logged yet.")

st.caption("Limitations: substring-based secret detection is not comprehensive; approval is simulated; log is session-local; no real LLM, email, file system, or external tool is connected.")
