"""Aligned report generator for ProShield-AI.

Synced with detector, incident_engine, attacker_intelligence, and predictor.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

UNKNOWN = "Unknown"

# ─────────────────────────────────────────────────────────
# Defensive actions (aligned with stages)
# ─────────────────────────────────────────────────────────

DEFENSIVE_ACTIONS: Dict[str, str] = {
    "Reconnaissance": "Block scanning IPs and enable IDS alerts.",
    "Initial Access": "Enforce MFA and review login attempts.",
    "Credential Access": "Lock accounts and rotate credentials.",
    "Privilege Escalation": "Audit admin access and patch vulnerabilities.",
    "Lateral Movement": "Segment network and monitor east-west traffic.",
    "Collection": "Enable DLP and restrict sensitive file access.",
    "Exfiltration": "Block outbound traffic and inspect transfers.",
    "Impact": "Isolate system and initiate incident response.",
}

# ─────────────────────────────────────────────────────────
# SINGLE EVENT REPORT
# ─────────────────────────────────────────────────────────

def generate_report(
    event: Dict[str, Any],
    prediction: Dict[str, Any],
    mitre_info: Dict[str, Any],
    incident: Dict[str, Any] = None,
    attacker: Dict[str, Any] = None,
) -> str:

    stage = (incident or {}).get("attack_stage", UNKNOWN)
    severity = event.get("severity", UNKNOWN)
    risk_score = event.get("risk_score", UNKNOWN)

    predicted_next = prediction.get("predicted_next") or UNKNOWN

    tactic = mitre_info.get("tactic", UNKNOWN)
    technique = mitre_info.get("technique_name", UNKNOWN)

    defensive_action = DEFENSIVE_ACTIONS.get(stage, "Review logs and apply security controls.")

    # Optional enrichment
    attack_speed = (incident or {}).get("attack_speed", UNKNOWN)
    correlation = (incident or {}).get("correlation_strength", 0.0)

    attack_style = (attacker or {}).get("attack_style", UNKNOWN)
    campaign_type = (attacker or {}).get("campaign_type", UNKNOWN)
    attacker_id = (attacker or {}).get("attacker_id", UNKNOWN)
    behavior_patterns = (attacker or {}).get("behavior_patterns", [])
    behavior_text = ", ".join(behavior_patterns) if behavior_patterns else UNKNOWN

    separator = "=" * 60

    return (
        f"{separator}\n"
        f"  ProShield-AI — Threat Intelligence Report\n"
        f"{separator}\n"
        f"  Timestamp        : {event.get('timestamp', UNKNOWN)}\n"
        f"  Source IP        : {event.get('source_ip', UNKNOWN)}\n"
        f"  Destination IP   : {event.get('destination_ip', UNKNOWN)}\n"
        f"  Activity         : {event.get('activity_type', UNKNOWN)}\n"
        f"{'-'*60}\n"
        f"  Risk Score       : {risk_score}\n"
        f"  Severity         : {severity}\n"
        f"{'-'*60}\n"
        f"  Attack Stage     : {stage}\n"
        f"  Attack Speed     : {attack_speed}\n"
        f"  Correlation      : {round(correlation, 2)}\n"
        f"{'-'*60}\n"
        f"  MITRE Technique  : {technique}\n"
        f"  MITRE Tactic     : {tactic}\n"
        f"{'-'*60}\n"
        f"  Predicted Next   : {predicted_next}\n"
        f"{'-'*60}\n"
        f"  Attack Style     : {attack_style}\n"
        f"  Campaign Type    : {campaign_type}\n"
        f"  Attacker ID      : {attacker_id}\n"
        f"  Behavior Pattern : {behavior_text}\n"
        f"{'-'*60}\n"
        f"  Recommended      : {defensive_action}\n"
        f"{separator}\n"
    )

# ─────────────────────────────────────────────────────────
# PIPELINE REPORT BUILDER
# ─────────────────────────────────────────────────────────

def build_report(
    logs: List[Dict[str, Any]],
    suspicious_events: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    mitre_techniques: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]] = None,
    attackers: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    event_reports = []

    for i, event in enumerate(suspicious_events):
        prediction = predictions[i] if i < len(predictions) else {}
        mitre_info = mitre_techniques[i] if i < len(mitre_techniques) else {}
        # Match incident by source_ip (simple mapping)
        incident = None
        if incidents:
            for inc in incidents:
                if inc.get("source_ip") == event.get("source_ip"):
                    incident = inc
                    break

        # match attacker by incident_id
        attacker = None
        if attackers and incident:
            for atk in attackers:
                if incident.get("incident_id") in atk.get("incident_ids", []):
                    attacker = atk
                    break

        event_reports.append(
            generate_report(event, prediction, mitre_info, incident, attacker)
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_logs": len(logs),
            "suspicious_events": len(suspicious_events),
        },
        "suspicious_events": suspicious_events,
        "predictions": predictions,
        "mitre_techniques": mitre_techniques,
        "incidents": incidents or [],
        "attackers": attackers or [],
        "event_reports": event_reports,
    }

# ─────────────────────────────────────────────────────────
# MARKDOWN EXPORT
# ─────────────────────────────────────────────────────────

def report_to_markdown(report: Dict[str, Any]) -> str:

    lines = [
        "# ProShield-AI — Threat Intelligence Report",
        "",
        f"Generated At: {report.get('generated_at')}",
        "",
        "## Summary",
        f"- Total Logs        : {report['summary']['total_logs']}",
        f"- Suspicious Events : {report['summary']['suspicious_events']}",
        "",
        "## Detailed Reports",
        ""
    ]

    for r in report.get("event_reports", []):
        lines.append("```")
        lines.append(r.strip())
        lines.append("```")
        lines.append("")

    return "\n".join(lines)