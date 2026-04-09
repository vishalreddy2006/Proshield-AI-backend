"""CTI mapper for ProShield-AI.

Maps an observed activity_type to its MITRE ATT&CK technique and tactic
by looking it up in data/mitre_mapping.json.
"""

import json
from typing import Any, Dict, List

MAPPING_PATH = "data/mitre_mapping.json"
UNKNOWN = "Unknown"


def _load_mapping(mapping_path: str = MAPPING_PATH) -> Dict[str, Any]:
    """Load and return the MITRE mapping dictionary from disk."""
    try:
        with open(mapping_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
            print(f"[cti_mapper] Expected a JSON object in {mapping_path}.")
            return {}
    except FileNotFoundError:
        print(f"[cti_mapper] Mapping file not found: {mapping_path}")
        return {}
    except json.JSONDecodeError as exc:
        print(f"[cti_mapper] Invalid JSON in {mapping_path}: {exc}")
        return {}


def map_to_mitre(
    activity_type: str,
    mapping_path: str = MAPPING_PATH,
) -> Dict[str, str]:
    """Look up a single activity_type in the MITRE mapping file.

    Parameters
    ----------
    activity_type : str
        The activity observed in a log event (e.g. ``"port_scan"``).
    mapping_path : str
        Path to mitre_mapping.json. Defaults to ``data/mitre_mapping.json``.

    Returns
    -------
    dict with keys:
        * ``activity_type``  – normalised input value
        * ``technique_id``   – MITRE technique ID, or ``"Unknown"``
        * ``technique_name`` – human-readable technique name, or ``"Unknown"``
        * ``tactic``         – MITRE tactic, or ``"Unknown"``

    Examples
    --------
    >>> map_to_mitre("port_scan")
    {'activity_type': 'port_scan', 'technique_id': 'T1595',
     'technique_name': 'Active Scanning', 'tactic': 'Reconnaissance'}

    >>> map_to_mitre("unknown_event")
    {'activity_type': 'unknown_event', 'technique_id': 'Unknown',
     'technique_name': 'Unknown', 'tactic': 'Unknown'}
    """
    normalised = activity_type.strip().lower()
    mapping = _load_mapping(mapping_path)
    entry = mapping.get(normalised, {})

    result = {
        "activity_type":  normalised,
        "technique_id":   entry.get("technique_id",   UNKNOWN),
        "technique_name": entry.get("technique_name", UNKNOWN),
        "tactic":         entry.get("tactic",         UNKNOWN),
    }

    if entry:
        print(f"[cti_mapper] {normalised}  ->  {result['technique_id']} "
              f"({result['tactic']})")
    else:
        print(f"[cti_mapper] No MITRE mapping found for: '{normalised}'")

    return result


def map_events_to_mitre(
    suspicious_events: List[Dict[str, Any]],
    mapping_path: str = MAPPING_PATH,
) -> List[Dict[str, str]]:
    """Map a list of suspicious events to MITRE techniques.

    Calls ``map_to_mitre`` for each event and returns all results,
    including those that resolved to ``"Unknown"``.

    Parameters
    ----------
    suspicious_events : list[dict]
        Events flagged by the detector. Each must have an ``activity_type`` field.
    mapping_path : str
        Path to mitre_mapping.json.

    Returns
    -------
    list[dict]
        One mapping result per event (same order as input).
    """
    return [
        map_to_mitre(event.get("activity_type", ""), mapping_path)
        for event in suspicious_events
    ]
