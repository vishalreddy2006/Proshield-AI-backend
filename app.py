"""ProShield-AI — Streamlit Cyber Defense Dashboard."""

import json

import pandas as pd
import streamlit as st

import database
from attacker_intelligence import build_attacker_profiles
from cti_mapper import map_events_to_mitre
from detector import detect_anomalies
from incident_engine import build_incidents
from log_loader import load_logs
from predictor import predict_next_step
from report_generator import build_report, generate_report, report_to_markdown

DB_ROUTE_HANDLERS = {
    "/logs": database.get_logs,
    "/events": database.get_events,
    "/incidents": database.get_incidents,
    "/attackers": database.get_attackers,
    "/report": database.get_reports,
}

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ProShield-AI Cyber Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_page" not in st.session_state:
    st.session_state.current_page = "home"
if "home_warning" not in st.session_state:
    st.session_state.home_warning = ""

if st.session_state.current_page == "login":
    st.title("Security Analyst Login")
    st.caption("Sign in to access the SOC dashboard")

    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    login_col, register_col = st.columns(2)
    login_clicked = login_col.button("Login as Security Analyst", use_container_width=True)
    register_clicked = register_col.button("Register as Security Analyst", use_container_width=True)

    if register_clicked:
        register_result = database.create_user(email.strip(), password)
        if register_result.get("success"):
            st.success("Registration successful. Please login")
        else:
            st.error(register_result.get("message", "User already exists"))

    if login_clicked:
        user = database.get_user(email.strip())
        if user is None:
            st.error("User not registered")
        elif user.get("password") != password:
            st.error("Invalid password")
        else:
            st.session_state.authenticated = True
            st.session_state.current_page = "home"
            st.session_state.home_warning = ""
            st.rerun()

    if st.button("Continue as Guest", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_page = "home"
        st.session_state.home_warning = ""
        st.rerun()

    st.stop()

if st.session_state.current_page == "home":
    st.title("SOC Detection Platform")
    st.caption("Log analysis · SIEM triage · anomaly detection · MITRE ATT&CK mapping")

    st.markdown(
        """
        ProShield-AI is a security operations workflow that ingests logs, detects anomalies,
        maps suspicious activity to MITRE ATT&CK, and builds incident intelligence summaries.
        """
    )

    st.markdown("**Key Features**")
    st.markdown(
        """
        - Centralized security log analysis
        - AI-assisted anomaly detection and risk scoring
        - Incident and attacker intelligence correlation
        - MITRE ATT&CK tactic and technique mapping
        - Exportable incident reports
        """
    )

    open_dashboard = st.button("Open Dashboard", use_container_width=True)
    if open_dashboard:
        if st.session_state.authenticated:
            st.session_state.current_page = "dashboard"
            st.session_state.home_warning = ""
            st.rerun()
        else:
            st.session_state.home_warning = "Please login to access dashboard"

    if st.session_state.home_warning:
        st.warning(st.session_state.home_warning)

    if not st.session_state.authenticated:
        if st.button("Go to Login", use_container_width=True):
            st.session_state.current_page = "login"
            st.rerun()

    st.stop()

if st.session_state.current_page == "dashboard" and not st.session_state.authenticated:
    st.session_state.current_page = "login"
    st.rerun()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ ProShield-AI Cyber Defense Dashboard")
st.caption("AI-powered log analysis · anomaly detection · MITRE ATT&CK mapping")
st.divider()

# ── Sidebar controls ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    if st.button("⬅ Home", use_container_width=True):
        st.session_state.current_page = "home"
        st.rerun()
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_page = "login"
        st.rerun()
    st.divider()
    log_path = st.text_input("Log file path", value="data/sample_logs.json")
    save_logs_to_db = st.checkbox("Save loaded logs to MongoDB", value=True)
    save_events_to_db = st.checkbox("Save detected events to MongoDB", value=True)
    save_incidents_to_db = st.checkbox("Save incidents to MongoDB", value=True)
    save_attackers_to_db = st.checkbox("Save attackers to MongoDB", value=True)
    save_report_to_db = st.checkbox("Save incident report to MongoDB", value=True)
    st.divider()
    st.caption("Backend Route Viewer")
    selected_route = st.selectbox("Route", options=list(DB_ROUTE_HANDLERS.keys()), index=0)
    load_route_data = st.button("Load Route Data", use_container_width=True)
    st.divider()
    st.info("Click **Load Logs** to start the analysis pipeline.")

# ── Session state — keeps results across Streamlit reruns ─────────────────────
if "report" not in st.session_state:
    st.session_state.report = None
if "logs" not in st.session_state:
    st.session_state.logs = []
if "incidents" not in st.session_state:
    st.session_state.incidents = []
if "attackers" not in st.session_state:
    st.session_state.attackers = []
if "route_rows" not in st.session_state:
    st.session_state.route_rows = []
if "route_name" not in st.session_state:
    st.session_state.route_name = None
if "db_log_save_count" not in st.session_state:
    st.session_state.db_log_save_count = 0
if "db_log_save_failed" not in st.session_state:
    st.session_state.db_log_save_failed = 0

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Load Logs
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("① Load Logs")

st.markdown("**Upload Security Logs**")
uploaded_log_file = st.file_uploader(
    "Upload a JSON log file (optional)",
    type=["json"],
    help="If uploaded, this file is used instead of the path in Settings.",
)

if load_route_data:
    if database.connect():
        if selected_route == "/events":
            backfill_fn = getattr(database, "backfill_zero_scored_events", None)
            if callable(backfill_fn):
                repaired_count = backfill_fn()
                if repaired_count > 0:
                    st.info(f"Backfilled score fields for {repaired_count} legacy event(s).")
        route_handler = DB_ROUTE_HANDLERS[selected_route]
        st.session_state.route_rows = route_handler() or []
        st.session_state.route_name = selected_route
    else:
        st.warning("MongoDB connection failed. Unable to load route data.")

if st.button("📂 Load Logs", use_container_width=True):
    if uploaded_log_file is not None:
        try:
            loaded_logs = json.load(uploaded_log_file)
            if not isinstance(loaded_logs, list):
                st.warning("Uploaded JSON must contain a list of log objects.")
                st.stop()
        except json.JSONDecodeError:
            st.warning("Uploaded file is not valid JSON.")
            st.stop()
    else:
        loaded_logs = load_logs(log_path)

    if not loaded_logs:
        st.warning("No valid logs loaded. Check the file path and JSON structure.")
        st.stop()

    saved_count = 0
    failed_count = 0
    if save_logs_to_db:
        if database.connect():
            for log in loaded_logs:
                if database.save_log(log):
                    saved_count += 1
                else:
                    failed_count += 1
        else:
            failed_count = len(loaded_logs)
            st.warning("MongoDB connection failed. Continuing analysis without saving logs.")

    # Run the full pipeline and cache results in session state
    all_events = detect_anomalies(loaded_logs)
    all_incidents = build_incidents(all_events)
    all_attackers = build_attacker_profiles(all_incidents)

    incident_by_source = {}
    for inc in all_incidents:
        src = inc.get("source_ip")
        if src and src not in incident_by_source:
            incident_by_source[src] = inc

    suspicious   = [e for e in all_events if e.get("label") == "suspicious"]
    predictions = []
    for event in suspicious:
        matched_incident = incident_by_source.get(event.get("source_ip"), {})
        predictions.append(
            predict_next_step(
                activity_type=event.get("activity_type", ""),
                attack_stage=matched_incident.get("attack_stage"),
                stage_progression=matched_incident.get("stage_progression"),
            )
        )

    mitre        = map_events_to_mitre(suspicious)
    report       = build_report(
        loaded_logs,
        suspicious,
        predictions,
        mitre,
        incidents=all_incidents,
        attackers=all_attackers,
    )
    report["event_reports"] = [
        generate_report(event, prediction, mitre_info)
        for event, prediction, mitre_info in zip(suspicious, predictions, mitre)
    ]

    if database.connect():
        if save_events_to_db:
            for event in all_events:
                database.save_event(event)
        if save_incidents_to_db:
            for incident in all_incidents:
                database.save_incident(incident)
        if save_attackers_to_db:
            for attacker in all_attackers:
                database.save_attacker(attacker)

    st.session_state.logs = all_events   # enriched with label + anomaly_score + risk_score + severity
    st.session_state.incidents = all_incidents
    st.session_state.attackers = all_attackers
    st.session_state.report = report
    st.session_state.db_log_save_count = saved_count
    st.session_state.db_log_save_failed = failed_count
    st.success(f"✅ Loaded **{len(loaded_logs)}** log(s) — **{len(suspicious)}** suspicious event(s) detected.")

# Nothing to show until logs are loaded
if not st.session_state.report:
    st.info("No analysis run yet. Enter a log file path and click **Load Logs**.")
    st.stop()

report = st.session_state.report
logs   = st.session_state.logs
incidents = st.session_state.incidents
attackers = st.session_state.attackers

incident_by_source = {}
for inc in incidents:
    src = inc.get("source_ip")
    if src and src not in incident_by_source:
        incident_by_source[src] = inc

attacker_by_incident_id = {}
for attacker in attackers:
    for incident_id in attacker.get("incident_ids", []):
        attacker_by_incident_id[incident_id] = attacker

if st.session_state.route_name:
    st.subheader(f"Backend Route Data — {st.session_state.route_name}")
    route_rows = st.session_state.route_rows
    if route_rows:
        st.dataframe(pd.DataFrame(route_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No data found for selected route.")
    st.divider()

# ── Summary metrics ───────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Logs",        report["summary"]["total_logs"])
c2.metric("Suspicious Events", report["summary"]["suspicious_events"])
c3.metric("Normal Events",
          report["summary"]["total_logs"] - report["summary"]["suspicious_events"])
critical_count = sum(1 for e in logs if e.get("severity") == "CRITICAL")
c4.metric("Critical Events", critical_count)

if save_logs_to_db:
    s1, s2 = st.columns(2)
    s1.metric("Logs Saved To MongoDB", st.session_state.db_log_save_count)
    s2.metric("Log Save Failures", st.session_state.db_log_save_failed)
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Log Table
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("② All Log Events")

log_df = pd.DataFrame(logs)
if not log_df.empty:
    log_df["incident_id"] = log_df["source_ip"].map(
        lambda ip: incident_by_source.get(ip, {}).get("incident_id")
    )
# Highlight suspicious rows with a simple colour map on the label column
def _colour_label(val: str) -> str:
    return "background-color: #ff4b4b; color: white;" if val == "suspicious" else ""


def _colour_severity(val: str) -> str:
    colour_map = {
        "LOW": "#2ecc71",
        "MEDIUM": "#f1c40f",
        "HIGH": "#e67e22",
        "CRITICAL": "#e74c3c",
    }
    if val in colour_map:
        return f"background-color: {colour_map[val]}; color: white;"
    return ""

display_cols = [c for c in
    ["timestamp", "source_ip", "destination_ip", "activity_type",
    "bytes_transferred", "label", "anomaly_score", "risk_score", "severity", "incident_id",
    "detection_quality", "detection_reason"]
    if c in log_df.columns]

subset_cols = []
if "label" in display_cols:
    subset_cols.append("label")
if "severity" in display_cols:
    subset_cols.append("severity")

styled_logs = log_df[display_cols].style
if "label" in subset_cols:
    styled_logs = styled_logs.applymap(_colour_label, subset=["label"])
if "severity" in subset_cols:
    styled_logs = styled_logs.applymap(_colour_severity, subset=["severity"])

st.dataframe(
    styled_logs,
    use_container_width=True,
    hide_index=True,
)
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Anomaly Detection Results
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("③ Anomaly Detection Results")

if report["suspicious_events"]:
    anom_df = pd.DataFrame(report["suspicious_events"])
    if not anom_df.empty:
        anom_df["incident_id"] = anom_df["source_ip"].map(
            lambda ip: incident_by_source.get(ip, {}).get("incident_id")
        )
    anom_cols = [c for c in
        ["timestamp", "source_ip", "destination_ip", "activity_type",
         "bytes_transferred", "anomaly_score", "risk_score", "severity", "incident_id",
         "detection_quality", "detection_reason"]
        if c in anom_df.columns]
    styled_anom = anom_df[anom_cols].style
    if "severity" in anom_cols:
        styled_anom = styled_anom.applymap(_colour_severity, subset=["severity"])
    st.dataframe(styled_anom, use_container_width=True, hide_index=True)
else:
    st.success("No anomalies detected in the loaded logs.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Incident Intelligence
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("④ Incident Intelligence")

if incidents:
    incident_df = pd.DataFrame(incidents)
    if not incident_df.empty:
        incident_df["stage_progression"] = incident_df["stage_progression"].apply(
            lambda x: " -> ".join(x) if isinstance(x, list) else x
        )
        incident_df["attacker_id"] = incident_df["incident_id"].map(
            lambda iid: attacker_by_incident_id.get(iid, {}).get("attacker_id", "Unknown")
        )

    incident_cols = [c for c in
        [
            "incident_id", "source_ip", "attack_stage", "stage_progression", "risk_score",
            "severity", "confidence", "attack_speed", "correlation_strength",
            "first_seen", "last_seen", "attacker_id",
        ]
        if c in incident_df.columns
    ]

    styled_incidents = incident_df[incident_cols].style
    if "severity" in incident_cols:
        styled_incidents = styled_incidents.applymap(_colour_severity, subset=["severity"])
    st.dataframe(styled_incidents, use_container_width=True, hide_index=True)
else:
    st.info("No incidents available for current run.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Attacker Intelligence
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑤ Attacker Intelligence")

if attackers:
    attacker_df = pd.DataFrame(attackers)
    if not attacker_df.empty:
        attacker_df["source_ips"] = attacker_df["source_ips"].apply(
            lambda x: ", ".join(x) if isinstance(x, list) else x
        )
        attacker_df["behavior_patterns"] = attacker_df["behavior_patterns"].apply(
            lambda x: ", ".join(x) if isinstance(x, list) else x
        )

    attacker_cols = [c for c in
        [
            "attacker_id", "source_ips", "incident_count", "attack_style", "skill_level",
            "campaign_type", "max_stage_reached", "behavior_patterns",
            "correlation_strength", "temporal_behavior",
        ]
        if c in attacker_df.columns
    ]
    st.dataframe(attacker_df[attacker_cols], use_container_width=True, hide_index=True)
else:
    st.info("No attacker profiles available for current run.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Predicted Next Attacker Action
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑥ Predicted Next Attacker Action")

if report["predictions"]:
    pred_rows = [
        {
            "Observed Activity": p["activity_type"],
            "Predicted Next Step": p["predicted_next"] or "Unknown",
            "Mapped": "✅" if p["known"] else "❓",
        }
        for p in report["predictions"]
    ]
    st.table(pd.DataFrame(pred_rows))
else:
    st.info("No predictions — no suspicious events were found.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7 — MITRE Tactic Mapping
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑦ MITRE ATT&CK Tactic Mapping")

if report["mitre_techniques"]:
    mitre_rows = [
        {
            "Activity":       m.get("activity_type", "—"),
            "Technique ID":   m.get("technique_id", "Unknown"),
            "Technique Name": m.get("technique_name", "Unknown"),
            "Tactic":         m.get("tactic", "Unknown"),
        }
        for m in report["mitre_techniques"]
    ]
    st.table(pd.DataFrame(mitre_rows))
else:
    st.info("No MITRE mappings — no suspicious events were found.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 8 — Generate Incident Report
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑧ Generate Incident Report")

if st.button("📄 Generate Incident Report", use_container_width=True):
    if report.get("event_reports"):
        for i, text_report in enumerate(report["event_reports"], start=1):
            with st.expander(f"Event {i} — {report['suspicious_events'][i - 1].get('activity_type', '')}"):
                st.code(text_report, language=None)
    else:
        st.info("No individual event reports — no suspicious events detected.")

    markdown_report = report_to_markdown(report)
    st.download_button(
        label="⬇️ Download Full Report (.md)",
        data=markdown_report,
        file_name="proshield_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

    incident_report_text = "\n\n".join(report.get("event_reports", []))
    if not incident_report_text:
        incident_report_text = "No suspicious events detected."

    st.download_button(
        label="⬇️ Download Incident Report",
        data=incident_report_text,
        file_name="incident_report.txt",
        mime="text/plain",
        use_container_width=True,
    )

    if save_report_to_db:
        if database.connect():
            inserted_id = database.save_report(report)
            if inserted_id:
                st.success(f"Report saved to MongoDB · ID: {inserted_id}")
            else:
                st.error("Report was not saved — insert failed.")
        else:
            st.error("MongoDB connection failed. Report not saved.")
