"""Incident Intelligence Engine for ProShield-AI.

Transforms event-level detections into incident-level intelligence by:
- Grouping related events into incidents
- Building attack chain sequences
- Computing incident risk and confidence
- Generating actionable recommendations
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK STAGE MAPPING
# ══════════════════════════════════════════════════════════════════════════════

ATTACK_STAGES = {
    "Reconnaissance": ["port_scan", "reconnaissance", "network_scan"],
    "Initial Access": ["login_attempt", "exploit", "phishing"],
    "Credential Access": ["failed_login", "credential_dumping", "brute_force"],
    "Privilege Escalation": ["privilege_escalation", "sudo_abuse"],
    "Lateral Movement": ["lateral_movement", "remote_execution"],
    "Collection": ["file_access", "data_collection", "screen_capture"],
    "Exfiltration": ["data_exfiltration", "data_transfer", "c2_communication"],
    "Impact": ["malware_activity", "ransomware", "data_destruction"],
}

# Reverse mapping: activity_type -> stage
ACTIVITY_TO_STAGE = {}
for stage, activities in ATTACK_STAGES.items():
    for activity in activities:
        ACTIVITY_TO_STAGE[activity] = stage

# Stage progression order (for risk calculation)
STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# Valid attack progressions (for sequence validation)
VALID_PROGRESSIONS = [
    ("Reconnaissance", "Initial Access"),
    ("Reconnaissance", "Credential Access"),
    ("Initial Access", "Credential Access"),
    ("Initial Access", "Privilege Escalation"),
    ("Credential Access", "Privilege Escalation"),
    ("Credential Access", "Initial Access"),
    ("Privilege Escalation", "Lateral Movement"),
    ("Privilege Escalation", "Collection"),
    ("Lateral Movement", "Collection"),
    ("Lateral Movement", "Privilege Escalation"),
    ("Collection", "Exfiltration"),
    ("Exfiltration", "Impact"),
]

MIN_CORRELATION_SCORE = 0.50


# ══════════════════════════════════════════════════════════════════════════════
# RECOMMENDED ACTIONS
# ══════════════════════════════════════════════════════════════════════════════

RECOMMENDED_ACTIONS = {
    ("Reconnaissance", "LOW"): "Monitor activity; enable port scan alerts.",
    ("Reconnaissance", "MEDIUM"): "Block scanning IP; review firewall rules.",
    ("Reconnaissance", "HIGH"): "Block IP at perimeter; enable threat intel feeds; investigate source.",
    ("Reconnaissance", "CRITICAL"): "Block IP; isolate affected subnet; investigate all connections.",
    
    ("Initial Access", "LOW"): "Monitor login attempts; review access logs.",
    ("Initial Access", "MEDIUM"): "Enforce MFA; review account permissions.",
    ("Initial Access", "HIGH"): "Lock affected accounts; enforce MFA; investigate login source.",
    ("Initial Access", "CRITICAL"): "Lock accounts; block IP; enforce MFA; rotate credentials; full investigation.",
    
    ("Credential Access", "LOW"): "Monitor failed logins; enable account lockout.",
    ("Credential Access", "MEDIUM"): "Lock account after failures; enforce password policy.",
    ("Credential Access", "HIGH"): "Lock affected accounts; block IP; enforce MFA; audit credential stores.",
    ("Credential Access", "CRITICAL"): "Lock all accounts from IP; block IP; rotate credentials; investigate credential exposure.",
    
    ("Privilege Escalation", "LOW"): "Review sudo logs; audit user permissions.",
    ("Privilege Escalation", "MEDIUM"): "Revoke excessive privileges; review privilege escalation attempts.",
    ("Privilege Escalation", "HIGH"): "Revoke privileges; isolate affected system; investigate exploit vectors.",
    ("Privilege Escalation", "CRITICAL"): "Isolate system; revoke all elevated access; patch vulnerabilities; full forensic analysis.",
    
    ("Lateral Movement", "LOW"): "Monitor east-west traffic; review internal connections.",
    ("Lateral Movement", "MEDIUM"): "Segment network; rotate credentials; review access paths.",
    ("Lateral Movement", "HIGH"): "Isolate affected systems; rotate credentials; block internal communication.",
    ("Lateral Movement", "CRITICAL"): "Emergency network segmentation; isolate all affected systems; rotate all credentials; incident response.",
    
    ("Collection", "LOW"): "Monitor file access patterns; enable DLP.",
    ("Collection", "MEDIUM"): "Restrict file permissions; enable file access auditing.",
    ("Collection", "HIGH"): "Revoke file access; enable DLP controls; investigate data accessed.",
    ("Collection", "CRITICAL"): "Revoke all access; isolate system; enable DLP; investigate data scope; legal notification.",
    
    ("Exfiltration", "LOW"): "Monitor outbound traffic; enable egress filtering.",
    ("Exfiltration", "MEDIUM"): "Block large transfers; enable DLP; review egress logs.",
    ("Exfiltration", "HIGH"): "Block outbound traffic from IP; isolate system; enable DLP; investigate data transferred.",
    ("Exfiltration", "CRITICAL"): "Emergency egress blocking; isolate system; enable DLP; full data breach protocol; legal/compliance notification.",
    
    ("Impact", "LOW"): "Monitor system integrity; enable EDR alerts.",
    ("Impact", "MEDIUM"): "Isolate affected system; deploy endpoint protection.",
    ("Impact", "HIGH"): "Isolate system; kill malicious processes; restore from backup; investigate malware.",
    ("Impact", "CRITICAL"): "Emergency isolation; disconnect from network; restore from backup; full incident response; malware analysis; legal notification.",
}


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL (GLOBAL STATE)
# ══════════════════════════════════════════════════════════════════════════════

_ml_model: Optional[GradientBoostingRegressor] = None


# ══════════════════════════════════════════════════════════════════════════════
# CORE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parse timestamp string into datetime object."""
    if isinstance(ts, datetime):
        return ts
    
    if not isinstance(ts, str):
        return None

    # Handle standard ISO 8601 including trailing Z timezone marker.
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        pass
    
    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    
    return None


def _group_events_by_incident(
    events: List[Dict[str, Any]],
    time_window_minutes: int = 5,
) -> List[List[Dict[str, Any]]]:
    """Group events into incidents based on source_ip and time proximity.
    
    Parameters
    ----------
    events : list[dict]
        Enriched events from detector.py
    time_window_minutes : int
        Time window in minutes for grouping (default: 5)
    
    Returns
    -------
    list[list[dict]]
        List of incident groups, each containing related events
    """
    if not events:
        return []
    
    # Sort events by timestamp
    sorted_events = sorted(
        events,
        key=lambda e: _parse_timestamp(e.get("timestamp")) or datetime.min
    )
    
    # Group by source IP
    ip_groups = defaultdict(list)
    for event in sorted_events:
        ip = event.get("source_ip", "unknown")
        ip_groups[ip].append(event)
    
    # Further group by time windows within each IP
    incidents = []
    time_delta = timedelta(minutes=time_window_minutes)
    
    for ip, ip_events in ip_groups.items():
        current_incident = []
        last_timestamp = None
        
        for event in ip_events:
            event_time = _parse_timestamp(event.get("timestamp"))
            
            if event_time is None:
                # If no valid timestamp, add to current incident
                current_incident.append(event)
                continue
            
            if last_timestamp is None:
                # First event in this IP group
                current_incident = [event]
                last_timestamp = event_time
            else:
                time_diff = event_time - last_timestamp
                
                if time_diff <= time_delta:
                    # Within time window - same incident
                    current_incident.append(event)
                    last_timestamp = event_time
                else:
                    # Time window exceeded - new incident
                    if current_incident:
                        incidents.append(current_incident)
                    current_incident = [event]
                    last_timestamp = event_time
        
        # Add final incident for this IP
        if current_incident:
            incidents.append(current_incident)
    
    return incidents


def _build_attack_chain(events: List[Dict[str, Any]]) -> Tuple[List[str], str, List[str]]:
    """Build attack chain from event sequence.
    
    Parameters
    ----------
    events : list[dict]
        Events in chronological order
    
    Returns
    -------
    tuple
        (activity_chain, current_stage, stage_progression)
    """
    activity_chain = []
    stages_seen = []
    
    for event in events:
        activity = event.get("activity_type", "unknown")
        activity_chain.append(activity)
        
        stage = ACTIVITY_TO_STAGE.get(activity.lower(), "Unknown")
        if stage not in stages_seen:
            stages_seen.append(stage)
    
    # Current stage = most advanced stage
    current_stage = "Unknown"
    max_stage_index = -1
    
    for stage in stages_seen:
        if stage in STAGE_ORDER:
            stage_index = STAGE_ORDER.index(stage)
            if stage_index > max_stage_index:
                max_stage_index = stage_index
                current_stage = stage
    
    return activity_chain, current_stage, stages_seen


def _calculate_sequence_quality(stage_progression: List[str]) -> float:
    """Calculate quality of attack sequence based on valid progressions.
    
    Parameters
    ----------
    stage_progression : list[str]
        Ordered list of attack stages
    
    Returns
    -------
    float
        Sequence quality score (0.0 - 1.0)
    """
    if len(stage_progression) <= 1:
        return 0.3  # Single stage = low confidence
    
    valid_transitions = 0
    total_transitions = len(stage_progression) - 1
    
    for i in range(total_transitions):
        stage_from = stage_progression[i]
        stage_to = stage_progression[i + 1]
        
        if (stage_from, stage_to) in VALID_PROGRESSIONS:
            valid_transitions += 1
        elif stage_from == stage_to:
            valid_transitions += 0.5  # Repeated stage = partial credit
    
    quality = valid_transitions / total_transitions if total_transitions > 0 else 0.0
    return min(1.0, quality)


def _calculate_incident_risk(
    events: List[Dict[str, Any]],
    stage_progression: List[str],
    current_stage: str,
) -> int:
    """Calculate deterministic incident risk score (0-100).
    
    Components:
    - Max event risk (40%)
    - Average event risk (20%)
    - Event count bonus (10%)
    - Critical activity presence (15%)
    - Stage progression bonus (15%)
    
    Parameters
    ----------
    events : list[dict]
        Events in the incident
    stage_progression : list[str]
        Attack stages seen
    current_stage : str
        Most advanced stage reached
    
    Returns
    -------
    int
        Risk score (0-100)
    """
    if not events:
        return 0
    
    # Component 1: Max event risk (40%)
    event_risks = [e.get("risk_score", 0) for e in events]
    max_risk = max(event_risks) if event_risks else 0
    max_risk_component = (max_risk / 100.0) * 40.0
    
    # Component 2: Average event risk (20%)
    avg_risk = sum(event_risks) / len(event_risks) if event_risks else 0
    avg_risk_component = (avg_risk / 100.0) * 20.0
    
    # Component 3: Event count bonus (10%)
    # More events = more confidence in incident
    event_count_bonus = min(10.0, len(events) * 2.0)
    
    # Component 4: Critical activity presence (15%)
    critical_activities = [
        "privilege_escalation",
        "data_exfiltration",
        "malware_activity",
        "lateral_movement",
    ]
    critical_count = sum(
        1 for e in events
        if e.get("activity_type", "").lower() in critical_activities
    )
    critical_component = min(15.0, critical_count * 7.5)
    
    # Component 5: Stage progression bonus (15%)
    # Later stages = higher risk
    stage_bonus = 0.0
    if current_stage in STAGE_ORDER:
        stage_index = STAGE_ORDER.index(current_stage)
        stage_bonus = (stage_index / len(STAGE_ORDER)) * 15.0
    
    total_risk = (
        max_risk_component +
        avg_risk_component +
        event_count_bonus +
        critical_component +
        stage_bonus
    )
    
    return max(0, min(100, int(round(total_risk))))


def _calculate_confidence(
    events: List[Dict[str, Any]],
    stage_progression: List[str],
    activity_chain: List[str],
) -> float:
    """Calculate confidence score (0.0 - 1.0).
    
    Factors:
    - Event count (more events = higher confidence)
    - Activity consistency (related activities)
    - Sequence quality (valid progressions)
    - Time coherence (reasonable intervals)
    
    Parameters
    ----------
    events : list[dict]
        Events in the incident
    stage_progression : list[str]
        Attack stages seen
    activity_chain : list[str]
        Activity sequence
    
    Returns
    -------
    float
        Confidence score (0.0 - 1.0)
    """
    # Factor 1: Event count (30%)
    event_count_score = min(1.0, len(events) / 10.0)
    event_count_component = event_count_score * 0.30
    
    # Factor 2: Activity consistency (20%)
    unique_activities = len(set(activity_chain))
    total_activities = len(activity_chain)
    consistency = 1.0 - (unique_activities / total_activities) if total_activities > 0 else 0.0
    consistency_component = consistency * 0.20
    
    # Factor 3: Sequence quality (30%)
    sequence_quality = _calculate_sequence_quality(stage_progression)
    sequence_component = sequence_quality * 0.30
    
    # Factor 4: Time coherence (20%)
    time_coherence = 0.5  # Default
    timestamps = [_parse_timestamp(e.get("timestamp")) for e in events]
    valid_timestamps = [t for t in timestamps if t is not None]
    
    if len(valid_timestamps) >= 2:
        intervals = [
            (valid_timestamps[i+1] - valid_timestamps[i]).total_seconds()
            for i in range(len(valid_timestamps) - 1)
        ]
        # Reasonable intervals (not too fast, not too slow)
        reasonable_intervals = sum(1 for t in intervals if 1 <= t <= 600)  # 1s to 10min
        time_coherence = reasonable_intervals / len(intervals) if intervals else 0.5
    
    time_component = time_coherence * 0.20
    
    total_confidence = (
        event_count_component +
        consistency_component +
        sequence_component +
        time_component
    )
    
    return max(0.0, min(1.0, total_confidence))


def _get_recommended_action(current_stage: str, severity: str) -> str:
    """Get recommended action based on attack stage and severity.
    
    Parameters
    ----------
    current_stage : str
        Current attack stage
    severity : str
        Incident severity (LOW, MEDIUM, HIGH, CRITICAL)
    
    Returns
    -------
    str
        Recommended action string
    """
    action = RECOMMENDED_ACTIONS.get((current_stage, severity))
    
    if action:
        return action
    
    # Fallback to generic recommendations
    if severity == "CRITICAL":
        return "Immediate isolation; block IP; full incident response protocol."
    elif severity == "HIGH":
        return "Isolate affected systems; investigate thoroughly; engage security team."
    elif severity == "MEDIUM":
        return "Monitor closely; investigate activity; review security controls."
    else:
        return "Monitor activity; review logs; enable additional alerts."


def _extract_ml_features(
    events: List[Dict[str, Any]],
    stage_progression: List[str],
    current_stage: str,
) -> np.ndarray:
    """Extract ML features from incident for risk refinement.
    
    Parameters
    ----------
    events : list[dict]
        Incident events
    stage_progression : list[str]
        Attack stages
    current_stage : str
        Current stage
    
    Returns
    -------
    np.ndarray
        Feature vector [event_count, avg_risk, max_risk, stage_numeric, 
                        sequence_length, unique_activities, time_span]
    """
    event_count = len(events)
    
    risks = [e.get("risk_score", 0) for e in events]
    avg_risk = sum(risks) / len(risks) if risks else 0
    max_risk = max(risks) if risks else 0
    
    stage_numeric = STAGE_ORDER.index(current_stage) if current_stage in STAGE_ORDER else 0
    sequence_length = len(stage_progression)
    
    unique_activities = len(set(e.get("activity_type", "") for e in events))
    
    # Time span (in minutes)
    timestamps = [_parse_timestamp(e.get("timestamp")) for e in events]
    valid_timestamps = [t for t in timestamps if t is not None]
    time_span = 0.0
    if len(valid_timestamps) >= 2:
        time_span = (max(valid_timestamps) - min(valid_timestamps)).total_seconds() / 60.0
    
    features = np.array([
        event_count,
        avg_risk,
        max_risk,
        stage_numeric,
        sequence_length,
        unique_activities,
        time_span,
    ]).reshape(1, -1)
    
    return features


def _train_ml_model() -> GradientBoostingRegressor:
    """Train ML model on synthetic incident data for risk refinement.
    
    Returns
    -------
    GradientBoostingRegressor
        Trained model
    """
    # Generate synthetic training data based on rules
    np.random.seed(42)
    
    training_samples = []
    training_labels = []
    
    # Low-risk incidents
    for _ in range(50):
        event_count = np.random.randint(1, 3)
        avg_risk = np.random.uniform(10, 30)
        max_risk = np.random.uniform(20, 40)
        stage_numeric = np.random.randint(0, 2)
        sequence_length = 1
        unique_activities = np.random.randint(1, 2)
        time_span = np.random.uniform(1, 10)
        
        training_samples.append([
            event_count, avg_risk, max_risk, stage_numeric,
            sequence_length, unique_activities, time_span
        ])
        training_labels.append(np.random.uniform(15, 35))
    
    # Medium-risk incidents
    for _ in range(50):
        event_count = np.random.randint(2, 5)
        avg_risk = np.random.uniform(30, 50)
        max_risk = np.random.uniform(40, 60)
        stage_numeric = np.random.randint(2, 4)
        sequence_length = np.random.randint(2, 3)
        unique_activities = np.random.randint(2, 4)
        time_span = np.random.uniform(5, 20)
        
        training_samples.append([
            event_count, avg_risk, max_risk, stage_numeric,
            sequence_length, unique_activities, time_span
        ])
        training_labels.append(np.random.uniform(40, 60))
    
    # High-risk incidents
    for _ in range(50):
        event_count = np.random.randint(4, 8)
        avg_risk = np.random.uniform(50, 70)
        max_risk = np.random.uniform(60, 80)
        stage_numeric = np.random.randint(4, 6)
        sequence_length = np.random.randint(3, 5)
        unique_activities = np.random.randint(3, 6)
        time_span = np.random.uniform(10, 30)
        
        training_samples.append([
            event_count, avg_risk, max_risk, stage_numeric,
            sequence_length, unique_activities, time_span
        ])
        training_labels.append(np.random.uniform(60, 80))
    
    # Critical incidents
    for _ in range(50):
        event_count = np.random.randint(6, 15)
        avg_risk = np.random.uniform(70, 90)
        max_risk = np.random.uniform(80, 100)
        stage_numeric = np.random.randint(6, 8)
        sequence_length = np.random.randint(4, 8)
        unique_activities = np.random.randint(5, 10)
        time_span = np.random.uniform(15, 60)
        
        training_samples.append([
            event_count, avg_risk, max_risk, stage_numeric,
            sequence_length, unique_activities, time_span
        ])
        training_labels.append(np.random.uniform(80, 100))
    
    X = np.array(training_samples)
    y = np.array(training_labels)
    
    model = GradientBoostingRegressor(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    
    print("[incident_engine] ML model trained on 200 synthetic incidents.")
    return model


def _get_ml_refined_risk(
    events: List[Dict[str, Any]],
    stage_progression: List[str],
    current_stage: str,
    deterministic_risk: int,
) -> int:
    """Refine deterministic risk using ML model (70% deterministic + 30% ML).
    
    Parameters
    ----------
    events : list[dict]
        Incident events
    stage_progression : list[str]
        Attack stages
    current_stage : str
        Current stage
    deterministic_risk : int
        Base risk score (0-100)
    
    Returns
    -------
    int
        Refined risk score (0-100)
    """
    global _ml_model
    
    # Train model if not already trained
    if _ml_model is None:
        _ml_model = _train_ml_model()
    
    try:
        features = _extract_ml_features(events, stage_progression, current_stage)
        ml_prediction = _ml_model.predict(features)[0]
        
        # Combine: 70% deterministic + 30% ML
        refined_risk = 0.7 * deterministic_risk + 0.3 * ml_prediction
        return max(0, min(100, int(round(refined_risk))))
    
    except Exception as e:
        print(f"[incident_engine] ML refinement failed: {e}. Using deterministic risk.")
        return deterministic_risk


# ══════════════════════════════════════════════════════════════════════════════
# TEMPORAL INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

def compute_temporal_risk(events: List[Dict[str, Any]]) -> Tuple[float, str]:
    """Compute temporal risk based on attack speed and progression patterns.
    
    Fast attacks (< 5s avg) indicate automated/aggressive campaigns.
    Slow attacks (> 60s avg) indicate stealthy APT-style operations.
    
    Parameters
    ----------
    events : list[dict]
        Events in chronological order
    
    Returns
    -------
    tuple
        (temporal_risk_score, attack_speed)
        - temporal_risk_score: 0.0-1.0
        - attack_speed: "fast" | "normal" | "slow"
    """
    if len(events) < 2:
        # Single event - no temporal pattern
        return 0.3, "unknown"
    
    # Extract and sort timestamps
    timestamps = []
    for event in events:
        ts = _parse_timestamp(event.get("timestamp"))
        if ts:
            timestamps.append(ts)
    
    if len(timestamps) < 2:
        # No valid timestamps for comparison
        return 0.3, "unknown"
    
    # Calculate time gaps between consecutive events
    time_gaps = []
    for i in range(len(timestamps) - 1):
        gap_seconds = (timestamps[i + 1] - timestamps[i]).total_seconds()
        time_gaps.append(gap_seconds)
    
    # Calculate average time gap
    avg_gap = sum(time_gaps) / len(time_gaps)
    
    # Classify attack speed and assign risk
    if avg_gap < 5.0:
        # Fast automated attack (brute force, scanning, flooding)
        return 1.0, "fast"
    elif avg_gap < 60.0:
        # Normal attack speed (manual or semi-automated)
        return 0.5, "normal"
    else:
        # Slow stealthy attack (APT, patient reconnaissance)
        # IMPORTANT: Slow doesn't mean low risk - stealth is dangerous
        return 0.7, "slow"


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-IP CORRELATION
# ══════════════════════════════════════════════════════════════════════════════

def correlate_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate incidents across multiple source IPs to detect distributed attacks.
    
    Correlation factors:
    - Common destination IPs (same targets)
    - Time proximity (attacks within 10 minutes)
    - Activity similarity (shared attack techniques)
    
    Parameters
    ----------
    incidents : list[dict]
        List of incidents to correlate
    
    Returns
    -------
    list[dict]
        Incidents enriched with correlation data:
        - correlated_incidents: list[str] (incident IDs)
        - correlation_strength: float (0.0-1.0)
    """
    if len(incidents) < 2:
        # No correlation possible
        for incident in incidents:
            incident["correlated_incidents"] = []
            incident["correlation_strength"] = 0.0
        return incidents
    
    # Build correlation matrix
    correlation_map = {incident["incident_id"]: [] for incident in incidents}
    correlation_scores = {}
    
    # Compare each pair of incidents
    for i in range(len(incidents)):
        for j in range(i + 1, len(incidents)):
            incident_a = incidents[i]
            incident_b = incidents[j]

            # Correlate only risk-relevant incidents to reduce benign-link noise.
            risk_a = int(incident_a.get("risk_score", 0))
            risk_b = int(incident_b.get("risk_score", 0))
            if max(risk_a, risk_b) < 55:
                continue
            
            # Skip if same source IP (already grouped)
            if incident_a["source_ip"] == incident_b["source_ip"]:
                continue
            
            # Calculate correlation score
            score = _calculate_correlation_score(incident_a, incident_b)
            
            if score >= MIN_CORRELATION_SCORE:
                # Store bidirectional correlation
                id_a = incident_a["incident_id"]
                id_b = incident_b["incident_id"]
                
                correlation_map[id_a].append(id_b)
                correlation_map[id_b].append(id_a)
                
                correlation_scores[(id_a, id_b)] = score
                correlation_scores[(id_b, id_a)] = score
    
    # Enrich incidents with correlation data
    for incident in incidents:
        incident_id = incident["incident_id"]
        correlated_ids = correlation_map[incident_id]
        
        incident["correlated_incidents"] = correlated_ids
        
        # Correlation strength = max score among all correlations
        if correlated_ids:
            max_score = max(
                correlation_scores.get((incident_id, cid), 0.0)
                for cid in correlated_ids
            )
            incident["correlation_strength"] = round(max_score, 3)
        else:
            incident["correlation_strength"] = 0.0
    
    # Log correlation summary
    correlated_count = sum(1 for i in incidents if i["correlation_strength"] > 0.0)
    if correlated_count > 0:
        print(f"[incident_engine] Detected {correlated_count} correlated incidents (potential distributed attack).")
    
    return incidents


def _calculate_correlation_score(
    incident_a: Dict[str, Any],
    incident_b: Dict[str, Any],
) -> float:
    """Calculate correlation score between two incidents.
    
    Scoring components (sum to 1.0):
    - Same destination IP: +0.4
    - Time proximity (<10 min): +0.3
    - Activity similarity: +0.3
    
    Parameters
    ----------
    incident_a, incident_b : dict
        Incident objects to compare
    
    Returns
    -------
    float
        Correlation score (0.0-1.0)
    """
    score = 0.0
    component_hits = 0

    # Component 1: Common destination IPs (0.4 max)
    dst_ips_a = set()
    for event in incident_a["events"]:
        dst_ip = event.get("destination_ip")
        if dst_ip:
            dst_ips_a.add(dst_ip)
    
    dst_ips_b = set()
    for event in incident_b["events"]:
        dst_ip = event.get("destination_ip")
        if dst_ip:
            dst_ips_b.add(dst_ip)
    
    common_targets = dst_ips_a.intersection(dst_ips_b)
    if common_targets:
        min_target_count = max(1, min(len(dst_ips_a), len(dst_ips_b)))
        target_overlap = len(common_targets) / min_target_count
        score += min(1.0, target_overlap) * 0.45
        if target_overlap >= 0.35:
            component_hits += 1
    
    # Component 2: Time proximity (0.3 max)
    try:
        first_a = _parse_timestamp(incident_a["first_seen"])
        last_a = _parse_timestamp(incident_a["last_seen"])
        first_b = _parse_timestamp(incident_b["first_seen"])
        last_b = _parse_timestamp(incident_b["last_seen"])

        if first_a and last_a and first_b and last_b:
            # Use incident window distance rather than first_seen-only distance.
            if first_a > last_b:
                gap_minutes = (first_a - last_b).total_seconds() / 60.0
            elif first_b > last_a:
                gap_minutes = (first_b - last_a).total_seconds() / 60.0
            else:
                gap_minutes = 0.0

            if gap_minutes <= 30.0:
                score += max(0.0, 1.0 - (gap_minutes / 30.0)) * 0.25
                if gap_minutes <= 15.0:
                    component_hits += 1
    except Exception:
        pass
    
    # Component 3: Activity similarity (0.3 max)
    activities_a = set(incident_a["attack_chain"])
    activities_b = set(incident_b["attack_chain"])
    
    common_activities = activities_a.intersection(activities_b)
    union_activities = activities_a.union(activities_b)
    if union_activities:
        activity_similarity = len(common_activities) / len(union_activities)
        score += activity_similarity * 0.3
        if activity_similarity >= 0.3:
            component_hits += 1

    # Require at least two independent signals to avoid fake campaign links.
    if component_hits < 2:
        return 0.0
    
    return round(min(1.0, score), 3)


def build_incidents(
    events: List[Dict[str, Any]],
    time_window_minutes: int = 5,
    use_ml_refinement: bool = True,
) -> List[Dict[str, Any]]:
    """Build incident-level intelligence from event-level detections.
    
    This is the main entry point for the incident engine.
    
    Parameters
    ----------
    events : list[dict]
        Enriched events from detector.py with fields:
        - label, risk_score, severity, activity_type, timestamp, source_ip
    time_window_minutes : int
        Time window for grouping events (default: 5)
    use_ml_refinement : bool
        Whether to use ML model for risk refinement (default: True)
    
    Returns
    -------
    list[dict]
        List of incident objects, each containing:
        - incident_id (str)
        - source_ip (str)
        - event_count (int)
        - attack_chain (list[str])
        - attack_stage (str)
        - stage_progression (list[str])
        - risk_score (int, 0-100)
        - severity (str)
        - confidence (float, 0.0-1.0)
        - recommended_action (str)
        - time_span_minutes (float)
        - first_seen (str)
        - last_seen (str)
        - events (list[dict])
    """
    if not events:
        print("[incident_engine] No events to process.")
        return []
    
    # Group events into incidents
    incident_groups = _group_events_by_incident(events, time_window_minutes)
    
    incidents = []
    
    for group in incident_groups:
        if not group:
            continue
        
        # Build attack chain
        activity_chain, current_stage, stage_progression = _build_attack_chain(group)
        
        # Calculate deterministic risk
        deterministic_risk = _calculate_incident_risk(group, stage_progression, current_stage)
        
        # Refine with ML if enabled
        if use_ml_refinement:
            risk_score = _get_ml_refined_risk(group, stage_progression, current_stage, deterministic_risk)
        else:
            risk_score = deterministic_risk
        
        # ── TEMPORAL INTELLIGENCE INTEGRATION ──
        # Compute temporal risk based on attack speed
        temporal_risk, attack_speed = compute_temporal_risk(group)
        
        # Augment risk score with temporal component
        # Add up to 15 points based on temporal patterns
        temporal_bonus = int(temporal_risk * 15)
        risk_score = min(100, risk_score + temporal_bonus)
        
        # Map risk to severity
        if risk_score <= 25:
            severity = "LOW"
        elif risk_score <= 50:
            severity = "MEDIUM"
        elif risk_score <= 75:
            severity = "HIGH"
        else:
            severity = "CRITICAL"
        
        # Calculate confidence
        confidence = _calculate_confidence(group, stage_progression, activity_chain)
        
        # Get recommended action
        recommended_action = _get_recommended_action(current_stage, severity)
        
        # Extract temporal metadata
        timestamps = [_parse_timestamp(e.get("timestamp")) for e in group]
        valid_timestamps = [t for t in timestamps if t is not None]
        
        first_seen = min(valid_timestamps).isoformat() if valid_timestamps else "Unknown"
        last_seen = max(valid_timestamps).isoformat() if valid_timestamps else "Unknown"
        
        time_span_minutes = 0.0
        if len(valid_timestamps) >= 2:
            time_span_minutes = (max(valid_timestamps) - min(valid_timestamps)).total_seconds() / 60.0
        
        # Build incident object
        incident = {
            "incident_id": str(uuid.uuid4()),
            "source_ip": group[0].get("source_ip", "unknown"),
            "event_count": len(group),
            "attack_chain": activity_chain,
            "attack_stage": current_stage,
            "stage_progression": stage_progression,
            "risk_score": risk_score,
            "severity": severity,
            "confidence": round(confidence, 3),
            "recommended_action": recommended_action,
            "time_span_minutes": round(time_span_minutes, 2),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "temporal_risk": round(temporal_risk, 3),
            "attack_speed": attack_speed,
            "events": group,
        }
        
        incidents.append(incident)
    
    # Sort incidents by risk score (highest first)
    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    
    # ── MULTI-IP CORRELATION ──
    # Correlate incidents across different source IPs to detect distributed attacks
    incidents = correlate_incidents(incidents)
    
    print(f"[incident_engine] Built {len(incidents)} incident(s) from {len(events)} event(s).")
    return incidents


def get_incident_summary(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary statistics from incidents.
    
    Parameters
    ----------
    incidents : list[dict]
        List of incident objects
    
    Returns
    -------
    dict
        Summary statistics
    """
    if not incidents:
        return {
            "total_incidents": 0,
            "critical_incidents": 0,
            "high_risk_incidents": 0,
            "avg_confidence": 0.0,
            "most_common_stage": "None",
            "total_events": 0,
        }
    
    total_incidents = len(incidents)
    critical_incidents = sum(1 for i in incidents if i["severity"] == "CRITICAL")
    high_risk_incidents = sum(1 for i in incidents if i["risk_score"] >= 60)
    
    avg_confidence = sum(i["confidence"] for i in incidents) / total_incidents
    
    # Most common stage
    stage_counts = defaultdict(int)
    for incident in incidents:
        stage_counts[incident["attack_stage"]] += 1
    
    most_common_stage = max(stage_counts.items(), key=lambda x: x[1])[0] if stage_counts else "None"
    
    total_events = sum(i["event_count"] for i in incidents)
    
    return {
        "total_incidents": total_incidents,
        "critical_incidents": critical_incidents,
        "high_risk_incidents": high_risk_incidents,
        "avg_confidence": round(avg_confidence, 3),
        "most_common_stage": most_common_stage,
        "total_events": total_events,
    }
