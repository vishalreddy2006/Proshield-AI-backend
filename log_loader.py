"""
Aligned Log Loader for ProShield-AI

Ensures logs are:
- structurally valid
- normalized for downstream pipeline
- safe for temporal + ML processing
"""

import json
from typing import Any, Dict, List
from datetime import datetime

REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "activity_type",
    "bytes_transferred"
}


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _is_valid_timestamp(value: Any) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return True
    except:
        return False


def _normalize_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize fields for consistent downstream processing."""

    return {
        "timestamp": str(entry["timestamp"]),
        "source_ip": str(entry["source_ip"]),
        "destination_ip": str(entry["destination_ip"]),
        "activity_type": str(entry["activity_type"]).strip().lower(),
        "bytes_transferred": float(entry.get("bytes_transferred", 0)),
    }


# ─────────────────────────────────────────────────────────
# Main Loader
# ─────────────────────────────────────────────────────────

def load_logs(file_path: str = "data/sample_logs.json") -> List[Dict[str, Any]]:

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as e:
        print(f"[log_loader] Failed to load file: {e}")
        return []

    if not isinstance(raw, list):
        print("[log_loader] Expected JSON array.")
        return []

    valid_logs: List[Dict[str, Any]] = []
    skipped = 0

    for i, entry in enumerate(raw):

        if not isinstance(entry, dict):
            skipped += 1
            continue

        # Required fields
        if not REQUIRED_FIELDS.issubset(entry.keys()):
            skipped += 1
            continue

        # Timestamp validation
        if not _is_valid_timestamp(entry["timestamp"]):
            print(f"[log_loader] Invalid timestamp at index {i}")
            skipped += 1
            continue

        try:
            normalized = _normalize_log(entry)
            valid_logs.append(normalized)
        except Exception:
            skipped += 1
            continue

    print(f"[log_loader] Loaded {len(valid_logs)} logs ({skipped} skipped)")

    return valid_logs