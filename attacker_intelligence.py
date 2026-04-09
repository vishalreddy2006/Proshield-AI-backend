from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict, Counter


# ✅ MUST MATCH incident_engine.py
STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact"
]


def _parse_iso_timestamp(value: Any) -> Optional[datetime]:
    """Parse ISO timestamps safely, including trailing Z."""
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def build_attacker_profiles(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not incidents:
        return []

    parent = {}

    def find(x):
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    # Initialize
    for inc in incidents:
        parent[inc['incident_id']] = inc['incident_id']

    incident_map = {inc['incident_id']: inc for inc in incidents}

    # ✅ Strong IP grouping
    ip_groups = defaultdict(list)
    for inc in incidents:
        ip_groups[inc['source_ip']].append(inc['incident_id'])

    for ids in ip_groups.values():
        for i in range(len(ids) - 1):
            union(ids[i], ids[i + 1])

    # ✅ STRICT correlation (>= 0.5 ONLY)
    for inc in incidents:
        if inc.get('correlation_strength', 0) >= 0.5:
            for corr_id in inc.get('correlated_incidents', []):
                if corr_id in incident_map:
                    union(inc['incident_id'], corr_id)

    # ✅ OPTIMIZED time grouping (sliding window)
    sorted_incidents = sorted(
        incidents,
        key=lambda x: _parse_iso_timestamp(x.get('last_seen')) or datetime.min,
    )
    window = []

    for inc in sorted_incidents:
        current_time = _parse_iso_timestamp(inc.get('last_seen'))
        if current_time is None:
            current_time = datetime.min

        # remove old items (>10 min)
        window = [
            w for w in window
            if (
                current_time - (_parse_iso_timestamp(w.get('last_seen')) or datetime.min)
            ).total_seconds() <= 600
        ]

        for w in window:
            if inc['source_ip'] == w['source_ip']:
                union(inc['incident_id'], w['incident_id'])

        window.append(inc)

    # Grouping
    groups = defaultdict(list)
    for inc in incidents:
        root = find(inc['incident_id'])
        groups[root].append(inc)

    profiles = []
    for idx, group in enumerate(groups.values()):
        profiles.append(build_single_attacker_profile(group, idx))

    profiles.sort(key=lambda x: x['max_risk_score'], reverse=True)
    return profiles


def build_single_attacker_profile(incidents: List[Dict[str, Any]], attacker_idx: int) -> Dict[str, Any]:

    source_ips = sorted(set(inc.get('source_ip', 'unknown') for inc in incidents))
    incident_ids = sorted(inc.get('incident_id', 'unknown') for inc in incidents)

    primary_ip = source_ips[0].replace('.', '').replace(':', '')[:12]
    attacker_id = f"ATK-{primary_ip}-{attacker_idx:04d}"

    # Risk
    risk_scores = [float(inc.get('risk_score', 0)) for inc in incidents]
    avg_risk = sum(risk_scores) / len(risk_scores)
    max_risk = max(risk_scores)

    if avg_risk <= 25:
        severity = "LOW"
    elif avg_risk <= 50:
        severity = "MEDIUM"
    elif avg_risk <= 75:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    # Stage
    stages = [inc.get('attack_stage', 'Unknown') for inc in incidents]
    primary_stage = Counter(stages).most_common(1)[0][0]

    max_stage = primary_stage
    max_idx = -1
    for s in stages:
        if s in STAGE_ORDER:
            idx = STAGE_ORDER.index(s)
            if idx > max_idx:
                max_idx = idx
                max_stage = s

    # Skill
    skill_level = determine_skill_level(max_stage)

    # Attack style (IMPROVED)
    speeds = [inc.get('attack_speed', 'normal') for inc in incidents]
    event_counts = [inc.get('event_count', 0) for inc in incidents]

    speed_mode = Counter(speeds).most_common(1)[0][0]
    avg_events = sum(event_counts) / len(event_counts)
    depth = len(set(stages))
    corr = max(inc.get('correlation_strength', 0) for inc in incidents)

    attack_style = determine_attack_style(speed_mode, avg_events, depth, corr)

    # Behavior
    behavior_patterns = extract_behavior_patterns(incidents)
    temporal_behavior = determine_temporal_behavior(speeds)

    # Correlation
    correlation_strength = max(inc.get('correlation_strength', 0) for inc in incidents)
    is_distributed = len(source_ips) > 1

    # Campaign (FIXED)
    campaign_type = determine_campaign_type(incidents, source_ips, correlation_strength)

    return {
        "attacker_id": attacker_id,
        "source_ips": source_ips,
        "incident_ids": incident_ids,
        "incident_count": len(incidents),
        "avg_risk_score": round(avg_risk, 2),
        "max_risk_score": max_risk,
        "severity": severity,
        "attack_style": attack_style,
        "skill_level": skill_level,
        "campaign_type": campaign_type,
        "primary_stage": primary_stage,
        "max_stage_reached": max_stage,
        "behavior_patterns": behavior_patterns,
        "temporal_behavior": temporal_behavior,
        "correlation_strength": round(correlation_strength, 2),
        "is_distributed": is_distributed,
        "first_seen": min(inc['first_seen'] for inc in incidents),
        "last_seen": max(inc['last_seen'] for inc in incidents)
    }


def determine_skill_level(stage: str) -> str:
    if stage in ["Exfiltration", "Impact"]:
        return "Advanced"
    elif stage in ["Credential Access", "Privilege Escalation", "Lateral Movement"]:
        return "Intermediate"
    return "Low"


def determine_attack_style(speed, avg_events, depth, corr):
    if speed == "fast" and avg_events > 50:
        return "Automated / Brute Force"
    if speed == "slow" and depth >= 4:
        return "Stealth / APT"
    if depth >= 3 and corr >= 0.5:
        return "Multi-Stage Targeted Attack"
    return "Opportunistic"


def determine_campaign_type(incidents, ips, corr):
    if len(ips) > 1 and corr >= 0.5:
        return "Distributed Campaign"

    # repeated behavior check
    stage_sequences = [tuple(inc.get('stage_progression', [])) for inc in incidents]
    if len(stage_sequences) != len(set(stage_sequences)):
        return "Persistent Campaign"

    return "Single Attack"


def extract_behavior_patterns(incidents):
    patterns = set()
    for inc in incidents:
        for event in inc.get('attack_chain', []):
            patterns.add(event.lower())
    return sorted(patterns)


def determine_temporal_behavior(speeds):
    c = Counter(speeds)
    total = len(speeds)

    if total == 0:
        return "adaptive"

    if c.get('fast', 0) / total > 0.6:
        return "aggressive"
    if c.get('slow', 0) / total > 0.6:
        return "stealthy"
    return "adaptive"