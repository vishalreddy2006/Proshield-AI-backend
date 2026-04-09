"""
Attack-chain predictor for ProShield-AI.

Aligned with:
- detector.py (activity_type)
- incident_engine.py (attack_stage, stage_progression)
- attacker_intelligence.py (behavior context)

Provides:
- Activity-based prediction (fallback)
- Stage-based prediction (primary)
- Hybrid SOC-aware prediction
"""

from typing import Dict, Optional, List

# ─────────────────────────────────────────────────────────────────────────────
# ✅ MUST MATCH incident_engine.py
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# Activity → Next Step (fallback rules)
# ─────────────────────────────────────────────────────────────────────────────

NEXT_STEP_RULES: Dict[str, str] = {
    "port_scan": "credential_attack",
    "login_attempt": "privilege_escalation",
    "failed_login": "credential_attack",
    "privilege_escalation": "lateral_movement",
    "data_transfer": "data_exfiltration",
    "file_access": "data_exfiltration",
    "malware_activity": "persistence",
}

# ─────────────────────────────────────────────────────────────────────────────
# Stage → Next Stage (PRIMARY LOGIC)
# ─────────────────────────────────────────────────────────────────────────────

STAGE_TRANSITIONS: Dict[str, str] = {
    "Reconnaissance": "Initial Access",
    "Initial Access": "Credential Access",
    "Credential Access": "Privilege Escalation",
    "Privilege Escalation": "Lateral Movement",
    "Lateral Movement": "Collection",
    "Collection": "Exfiltration",
    "Exfiltration": "Impact",
}

ACTIVITY_TO_STAGE: Dict[str, str] = {
    "port_scan": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "login_attempt": "Initial Access",
    "failed_login": "Credential Access",
    "privilege_escalation": "Privilege Escalation",
    "lateral_movement": "Lateral Movement",
    "file_access": "Collection",
    "data_transfer": "Exfiltration",
    "data_exfiltration": "Exfiltration",
    "malware_activity": "Impact",
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN PREDICTOR
# ─────────────────────────────────────────────────────────────────────────────

def predict_next_step(
    activity_type: Optional[str] = None,
    attack_stage: Optional[str] = None,
    stage_progression: Optional[List[str]] = None
) -> Dict[str, Optional[str]]:
    """
    SOC-aligned attack prediction.

    Priority:
    1. Stage progression (most accurate)
    2. Current attack_stage
    3. activity_type fallback
    """

    activity = (activity_type or "").strip().lower()

    predicted_stage = None
    predicted_action = None
    method = "unknown"

    # ─────────────────────────────────────────────────────────
    # 1️⃣ Stage progression (BEST SIGNAL)
    # ─────────────────────────────────────────────────────────
    if stage_progression and len(stage_progression) > 0:
        last_stage = stage_progression[-1]

        if last_stage in STAGE_TRANSITIONS:
            predicted_stage = STAGE_TRANSITIONS[last_stage]
            method = "stage_progression"

    # ─────────────────────────────────────────────────────────
    # 2️⃣ Direct stage prediction
    # ─────────────────────────────────────────────────────────
    elif attack_stage in STAGE_TRANSITIONS:
        predicted_stage = STAGE_TRANSITIONS[attack_stage]
        method = "stage_based"

    # ─────────────────────────────────────────────────────────
    # 3️⃣ Activity fallback (WEAKEST)
    # ─────────────────────────────────────────────────────────
    elif activity in NEXT_STEP_RULES:
        predicted_action = NEXT_STEP_RULES[activity]
        method = "activity_based"

    # ─────────────────────────────────────────────────────────
    # 4️⃣ Activity -> Stage inference fallback
    # ─────────────────────────────────────────────────────────
    elif activity in ACTIVITY_TO_STAGE:
        inferred_stage = ACTIVITY_TO_STAGE[activity]
        predicted_stage = STAGE_TRANSITIONS.get(inferred_stage)
        if predicted_stage:
            method = "activity_inferred_stage"

    # ─────────────────────────────────────────────────────────
    # Final normalization
    # ─────────────────────────────────────────────────────────
    predicted = predicted_stage if predicted_stage else predicted_action

    if predicted:
        print(f"[predictor] ({method}) -> {predicted}")
    else:
        print(f"[predictor] No prediction available")

    return {
        "activity_type": activity,
        "attack_stage": attack_stage,
        "predicted_next": predicted,
        "prediction_type": method,
        "known": predicted is not None,
    }