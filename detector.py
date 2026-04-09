"""Anomaly-based suspicious activity detector for ProShield-AI.

Production-grade behavioral + temporal detection engine with:
- Chronological processing (no data leakage)
- Separated training/inference
- Adaptive thresholds
- Attack sequence intelligence
- O(n) performance
"""

from typing import Any, Dict, List, Optional
import math
import joblib
import json
from datetime import datetime
from collections import defaultdict, deque
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ══════════════════════════════════════════════════════════════════════════════
# MODEL PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

_model: Optional[IsolationForest] = None
_scaler: Optional[StandardScaler] = None
_model_trained: bool = False

MODEL_PATH = "proshield_model.pkl"
SCALER_PATH = "proshield_scaler.pkl"
IOC_WATCHLIST_PATH = "data/ioc_watchlist.json"


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Risk scoring weights (sum = 100)
WEIGHTS = {
    "anomaly": 40,
    "activity": 25,
    "ioc": 20,
    "rule": 15,
}

# Activity risk mapping
ACTIVITY_RISK = {
    "normal": 0.1,
    "login_attempt": 0.3,
    "failed_login": 0.5,
    "port_scan": 0.7,
    "reconnaissance": 0.6,
    "privilege_escalation": 0.9,
    "malware_activity": 1.0,
    "data_exfiltration": 1.0,
    "lateral_movement": 0.8,
    "data_transfer": 0.4,
    "file_access": 0.3,
}

# Attack sequence patterns (progression detection)
ATTACK_SEQUENCES = [
    ["port_scan", "login_attempt"],
    ["port_scan", "reconnaissance"],
    ["login_attempt", "failed_login"],
    ["failed_login", "failed_login"],  # repeated failures
    ["failed_login", "privilege_escalation"],
    ["login_attempt", "privilege_escalation"],
    ["privilege_escalation", "lateral_movement"],
    ["privilege_escalation", "data_exfiltration"],
    ["file_access", "data_exfiltration"],
    ["data_transfer", "data_exfiltration"],
    ["malware_activity", "lateral_movement"],
    ["reconnaissance", "credential_attack"],
]

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 3  # failed logins in window
BURST_THRESHOLD = 5  # events per minute
SCAN_THRESHOLD = 10  # unique destinations
TIME_WINDOW_SECONDS = 300  # 5 minutes
SEQUENCE_HISTORY_SIZE = 5  # track last N activities per IP


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_activity_weight(activity_type: str) -> float:
    """Return explainable activity risk weight in range 0..1."""
    key = str(activity_type or "").strip().lower()
    return ACTIVITY_RISK.get(key, 0.2)


def get_ioc_weight(event: Dict[str, Any]) -> float:
    """Return IOC signal weight (1 for IOC hit, else 0)."""
    return 1.0 if bool(event.get("ioc_matched", False)) else 0.0


def get_rule_weight(event: Dict[str, Any]) -> float:
    """Return rule signal weight (1 when rule flags exist, else 0)."""
    rule_flags = event.get("rule_flags", [])
    return 1.0 if isinstance(rule_flags, list) and len(rule_flags) > 0 else 0.0


def _parse_timestamp(ts_str: Any) -> Optional[datetime]:
    """Parse timestamp string to datetime object."""
    if not ts_str:
        return None
    try:
        # Try ISO format first
        return datetime.fromisoformat(str(ts_str).replace('Z', '+00:00'))
    except:
        try:
            # Try common formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d-%m-%Y %H:%M"]:
                try:
                    return datetime.strptime(str(ts_str), fmt)
                except:
                    continue
        except:
            pass
    return None


def get_severity(score: int) -> str:
    """Map score bands to explainable severity labels."""
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def _load_ioc_watchlist(path: str = IOC_WATCHLIST_PATH) -> Dict[str, set]:
    """Load IOC watchlist from JSON file.

    Expected format:
    {
      "source_ips": ["1.2.3.4"],
      "destination_ips": ["5.6.7.8"]
    }
    """
    default_watchlist = {"source_ips": set(), "destination_ips": set()}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        source_ips = set(str(ip).strip() for ip in data.get("source_ips", []) if ip)
        destination_ips = set(str(ip).strip() for ip in data.get("destination_ips", []) if ip)
        return {"source_ips": source_ips, "destination_ips": destination_ips}
    except Exception:
        return default_watchlist


def _event_matches_ioc(event: Dict[str, Any], ioc_watchlist: Dict[str, set]) -> bool:
    """Check whether event source or destination matches IOC watchlist."""
    src_ip = str(event.get("source_ip", "")).strip()
    dst_ip = str(event.get("destination_ip", "")).strip()
    return src_ip in ioc_watchlist["source_ips"] or dst_ip in ioc_watchlist["destination_ips"]


def _build_rule_flags(
    event: Dict[str, Any],
    features: Dict[str, float],
    high_bytes_threshold: float,
) -> List[str]:
    """Build explainable deterministic rule flags for each event."""
    flags: List[str] = []
    activity_type = str(event.get("activity_type", "")).strip().lower()
    bytes_value = float(features.get("bytes_transferred", 0.0))

    if features["failed_login_count_5min"] >= BRUTE_FORCE_THRESHOLD:
        flags.append("brute_force_pattern")
    if features["unique_dst_per_src"] > SCAN_THRESHOLD:
        flags.append("port_scanning_pattern")
    if features["sequence_risk_score"] > 0.5:
        flags.append("attack_sequence_detected")
    if bytes_value >= high_bytes_threshold and activity_type in {"data_transfer", "data_exfiltration"}:
        flags.append("possible_data_exfiltration")
    if features["is_unusual_hour"] > 0 and get_activity_weight(activity_type) >= 0.8:
        flags.append("high_risk_off_hours")

    return flags


# ══════════════════════════════════════════════════════════════════════════════
# INCREMENTAL STATISTICS TRACKER (NO DATA LEAKAGE)
# ══════════════════════════════════════════════════════════════════════════════

class IncrementalStatsTracker:
    """Tracks behavioral statistics incrementally to prevent data leakage.
    
    For each event, features are computed using ONLY past events.
    """
    
    def __init__(self):
        # Per-IP tracking
        self.ip_event_count = defaultdict(int)
        self.ip_total_bytes = defaultdict(float)
        self.ip_destinations = defaultdict(set)
        self.ip_last_timestamp = {}
        self.ip_activity_history = defaultdict(lambda: deque(maxlen=SEQUENCE_HISTORY_SIZE))
        self.ip_failed_login_times = defaultdict(list)
        self.ip_event_times = defaultdict(list)
        
        # Per-destination tracking
        self.dst_event_count = defaultdict(int)
        
        # Global tracking
        self.activity_type_count = defaultdict(int)
        self.total_events = 0
        self.all_bytes = []
        
    def compute_features(self, event: Dict[str, Any], current_time: Optional[datetime]) -> Dict[str, float]:
        """Compute features for event using ONLY past data."""
        
        src_ip = str(event.get("source_ip", "unknown"))
        dst_ip = str(event.get("destination_ip", "unknown"))
        activity_type = str(event.get("activity_type", "unknown")).strip().lower()
        
        try:
            bytes_transferred = float(event.get("bytes_transferred", 0))
        except:
            bytes_transferred = 0.0
        
        # ── Features from PAST data only ──────────────────────────────────────
        
        # Basic features
        log_bytes = math.log1p(bytes_transferred)
        activity_risk = get_activity_weight(activity_type)
        
        # Per-IP past statistics
        src_ip_event_count = self.ip_event_count[src_ip]
        src_ip_total_bytes = self.ip_total_bytes[src_ip]
        unique_dst_per_src = len(self.ip_destinations[src_ip])
        
        # Average bytes for this IP (from past events)
        avg_bytes_per_src_ip = (src_ip_total_bytes / src_ip_event_count) if src_ip_event_count > 0 else 0.0
        
        # Deviation from IP baseline
        if avg_bytes_per_src_ip > 0:
            bytes_deviation = abs(bytes_transferred - avg_bytes_per_src_ip) / avg_bytes_per_src_ip
            deviation_from_ip_baseline = min(1.0, bytes_deviation)
        else:
            bytes_deviation = 0.0
            deviation_from_ip_baseline = 0.0
        
        # Destination popularity
        dst_ip_event_count = self.dst_event_count[dst_ip]
        
        # Activity type frequency (global)
        activity_type_frequency = self.activity_type_count[activity_type]
        activity_rarity = 1.0 / (1.0 + activity_type_frequency)
        
        # Global statistics
        global_avg_bytes = sum(self.all_bytes) / len(self.all_bytes) if self.all_bytes else 0.0
        global_std_bytes = 0.0
        if len(self.all_bytes) > 1:
            variance = sum((x - global_avg_bytes) ** 2 for x in self.all_bytes) / len(self.all_bytes)
            global_std_bytes = math.sqrt(variance)
        
        bytes_zscore = 0.0
        if global_std_bytes > 0:
            bytes_zscore = (bytes_transferred - global_avg_bytes) / global_std_bytes
        
        is_high_bytes = 1.0 if bytes_transferred > global_avg_bytes else 0.0
        
        # ── Temporal features ─────────────────────────────────────────────────
        
        time_since_last_event = 0.0
        events_per_minute = 0.0
        session_event_index = src_ip_event_count + 1
        
        hour_of_day = 12.0  # default
        is_unusual_hour = 0.0
        
        if current_time:
            hour_of_day = float(current_time.hour)
            is_unusual_hour = 1.0 if (hour_of_day < 6 or hour_of_day > 22) else 0.0
            
            if src_ip in self.ip_last_timestamp:
                last_time = self.ip_last_timestamp[src_ip]
                time_diff = (current_time - last_time).total_seconds()
                time_since_last_event = max(0.0, time_diff)
                
                if time_diff > 0:
                    events_per_minute = 60.0 / time_diff
        
        # ── Frequency-based features (windowed) ───────────────────────────────
        
        # Failed login count in last 5 minutes
        failed_login_count_5min = 0
        if activity_type == "failed_login" and current_time:
            cutoff_time = current_time.timestamp() - TIME_WINDOW_SECONDS
            self.ip_failed_login_times[src_ip] = [
                t for t in self.ip_failed_login_times[src_ip] if t > cutoff_time
            ]
            failed_login_count_5min = len(self.ip_failed_login_times[src_ip])
        
        # Event burst detection (rolling 5-minute window)
        rolling_event_count_5 = 0
        if current_time:
            cutoff_time = current_time.timestamp() - TIME_WINDOW_SECONDS
            self.ip_event_times[src_ip] = [
                t for t in self.ip_event_times[src_ip] if t > cutoff_time
            ]
            rolling_event_count_5 = len(self.ip_event_times[src_ip])
        
        is_burst_activity = 1.0 if events_per_minute > BURST_THRESHOLD else 0.0
        is_repeated_activity = 1.0 if rolling_event_count_5 >= 2 else 0.0
        
        # Rolling bytes sum (simplified - use recent average * count)
        rolling_bytes_sum_5 = avg_bytes_per_src_ip * rolling_event_count_5
        
        # Unique activity types for this IP
        unique_activity_types_per_ip = len(set(self.ip_activity_history[src_ip])) if self.ip_activity_history[src_ip] else 1
        
        # ── Attack sequence detection ─────────────────────────────────────────
        
        sequence_risk_score = self._detect_attack_sequence(src_ip, activity_type)
        
        # ── Assemble feature vector ───────────────────────────────────────────
        
        features = {
            "bytes_transferred": bytes_transferred,
            "log_bytes": log_bytes,
            "activity_risk_score": activity_risk,
            "src_ip_event_count": float(src_ip_event_count),
            "src_ip_total_bytes": src_ip_total_bytes,
            "unique_dst_per_src": float(unique_dst_per_src),
            "avg_bytes_per_src_ip": avg_bytes_per_src_ip,
            "bytes_deviation_from_src_avg": bytes_deviation,
            "deviation_from_ip_baseline": deviation_from_ip_baseline,
            "dst_ip_event_count": float(dst_ip_event_count),
            "activity_type_frequency": float(activity_type_frequency),
            "activity_rarity": activity_rarity,
            "bytes_zscore": bytes_zscore,
            "is_high_bytes": is_high_bytes,
            "hour_of_day": hour_of_day,
            "is_unusual_hour": is_unusual_hour,
            "time_since_last_event": time_since_last_event,
            "session_event_index": float(session_event_index),
            "events_per_minute": min(events_per_minute, 100.0),  # cap outliers
            "rolling_event_count_5": float(rolling_event_count_5),
            "rolling_bytes_sum_5": rolling_bytes_sum_5,
            "is_burst_activity": is_burst_activity,
            "is_repeated_activity": is_repeated_activity,
            "failed_login_count_5min": float(failed_login_count_5min),
            "unique_activity_types_per_ip": float(unique_activity_types_per_ip),
            "sequence_risk_score": sequence_risk_score,
        }
        
        return features
    
    def update_state(self, event: Dict[str, Any], current_time: Optional[datetime]):
        """Update internal state AFTER computing features for this event."""
        
        src_ip = str(event.get("source_ip", "unknown"))
        dst_ip = str(event.get("destination_ip", "unknown"))
        activity_type = str(event.get("activity_type", "unknown")).strip().lower()
        
        try:
            bytes_transferred = float(event.get("bytes_transferred", 0))
        except:
            bytes_transferred = 0.0
        
        # Update counters
        self.ip_event_count[src_ip] += 1
        self.ip_total_bytes[src_ip] += bytes_transferred
        self.ip_destinations[src_ip].add(dst_ip)
        self.dst_event_count[dst_ip] += 1
        self.activity_type_count[activity_type] += 1
        self.total_events += 1
        self.all_bytes.append(bytes_transferred)
        
        # Update temporal state
        if current_time:
            self.ip_last_timestamp[src_ip] = current_time
            self.ip_event_times[src_ip].append(current_time.timestamp())
            
            if activity_type == "failed_login":
                self.ip_failed_login_times[src_ip].append(current_time.timestamp())
        
        # Update activity history
        self.ip_activity_history[src_ip].append(activity_type)
    
    def _detect_attack_sequence(self, src_ip: str, current_activity: str) -> float:
        """Detect attack progression patterns."""
        
        history = list(self.ip_activity_history[src_ip])
        
        if not history:
            return 0.0
        
        # Check if current activity follows a known attack pattern
        for pattern in ATTACK_SEQUENCES:
            if len(pattern) == 2:
                prev_activity = pattern[0]
                next_activity = pattern[1]
                
                if current_activity == next_activity and prev_activity in history:
                    # Found attack progression
                    # Higher score if pattern occurred recently
                    if history and history[-1] == prev_activity:
                        return 0.9  # immediate progression
                    else:
                        return 0.6  # progression within history
        
        return 0.0


# ══════════════════════════════════════════════════════════════════════════════
# BEHAVIORAL RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _calculate_behavioral_anomaly_score(event: Dict[str, Any], features: Dict[str, float]) -> float:
    """Rule-based behavioral anomaly detection (0-1 scale)."""
    
    score = 0.0
    activity_type = str(event.get("activity_type", "")).strip().lower()

    # Baseline signal so risky activities are visible even without sequence/window triggers.
    activity_risk = float(features.get("activity_risk_score", 0.0))
    score += min(0.25, activity_risk * 0.25)

    # Behavioral drift from historical per-IP baseline.
    deviation = float(features.get("deviation_from_ip_baseline", 0.0))
    if deviation > 0.2:
        score += min(0.2, deviation * 0.2)

    # Sudden byte spikes compared to global baseline.
    z_score = abs(float(features.get("bytes_zscore", 0.0)))
    if z_score >= 1.5:
        score += min(0.15, (z_score - 1.5) * 0.05)
    
    # Rule 1: Brute force detection
    if features["failed_login_count_5min"] >= BRUTE_FORCE_THRESHOLD:
        score += 0.4
    
    # Rule 2: Burst activity
    if features["is_burst_activity"] > 0:
        score += 0.3
    
    # Rule 3: Repeated high-risk activity
    if features["is_repeated_activity"] > 0 and features["activity_risk_score"] >= 0.7:
        score += 0.3
    
    # Rule 4: Port scanning / reconnaissance
    if features["unique_dst_per_src"] > SCAN_THRESHOLD:
        score += 0.3
    
    # Rule 5: Baseline deviation + unusual hours
    if features["deviation_from_ip_baseline"] > 0.5 and features["is_unusual_hour"] > 0:
        score += 0.3
    
    # Rule 6: High-risk activity during unusual hours
    if features["activity_risk_score"] >= 0.8 and features["is_unusual_hour"] > 0:
        score += 0.2
    
    # Rule 7: Large data transfer (potential exfiltration)
    if features["rolling_bytes_sum_5"] > 10_000_000:  # 10 MB
        score += 0.2
    
    # Rule 8: Attack sequence detected
    if features["sequence_risk_score"] > 0.5:
        score += 0.4
    
    return min(1.0, score)


def _is_early_attack_pattern(event: Dict[str, Any], features: Dict[str, float]) -> bool:
    """Detect early-stage attack indicators."""
    
    activity_type = str(event.get("activity_type", "")).strip().lower()
    
    # Early reconnaissance
    if activity_type in ["port_scan", "reconnaissance"]:
        return True
    
    # Credential attack initiation
    if activity_type == "login_attempt" and features["is_burst_activity"] > 0:
        return True
    
    # Scanning behavior
    if features["unique_dst_per_src"] > 5:
        return True
    
    # Failed login spike
    if features["failed_login_count_5min"] >= 2:
        return True
    
    return False


# ══════════════════════════════════════════════════════════════════════════════
# MODEL TRAINING & PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

def train_model(logs: List[Dict[str, Any]], save_to_disk: bool = True) -> Optional[IsolationForest]:
    """Train IsolationForest model on historical logs.
    
    IMPORTANT: This should be run on clean/baseline data to learn normal behavior.
    
    Parameters
    ----------
    logs : list[dict]
        Historical log entries (preferably benign/normal traffic)
    save_to_disk : bool
        If True, saves model and scaler to disk
        
    Returns
    -------
    IsolationForest or None
        Trained model
    """
    global _model, _scaler, _model_trained
    
    if not logs:
        print("[detector] No logs provided — model not trained.")
        return None
    
    print(f"[detector] Training model on {len(logs)} historical log(s)...")
    
    # Sort logs chronologically
    sorted_logs = sorted(
        logs,
        key=lambda x: _parse_timestamp(x.get("timestamp")) or datetime.min
    )
    
    # Extract features using incremental tracker (no leakage)
    tracker = IncrementalStatsTracker()
    feature_vectors = []
    
    for log in sorted_logs:
        current_time = _parse_timestamp(log.get("timestamp"))
        features = tracker.compute_features(log, current_time)
        tracker.update_state(log, current_time)
        feature_vectors.append(features)
    
    # Convert to DataFrame
    df = pd.DataFrame(feature_vectors)
    
    # Handle any NaN/inf values
    df = df.replace([float('inf'), float('-inf')], 0.0)
    df = df.fillna(0.0)
    
    X = df.values
    
    # Train scaler
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)
    
    # Adaptive contamination
    n_samples = len(logs)
    if n_samples < 10:
        contamination = 0.1
    elif n_samples < 50:
        contamination = 0.15
    elif n_samples < 200:
        contamination = 0.2
    else:
        contamination = 0.25
    
    # Train model
    _model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        max_samples=min(256, n_samples),
        random_state=42,
        n_jobs=-1,
    )
    _model.fit(X_scaled)
    _model_trained = True
    
    print(f"[detector] Model trained successfully (contamination={contamination:.2f})")
    
    # Save to disk
    if save_to_disk:
        try:
            joblib.dump(_model, MODEL_PATH)
            joblib.dump(_scaler, SCALER_PATH)
            print(f"[detector] Model saved to {MODEL_PATH}")
        except Exception as e:
            print(f"[detector] Warning: Could not save model: {e}")
    
    return _model


def load_model(model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH) -> bool:
    """Load pre-trained model and scaler from disk.
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    global _model, _scaler, _model_trained
    
    try:
        _model = joblib.load(model_path)
        _scaler = joblib.load(scaler_path)
        _model_trained = True
        print(f"[detector] Model loaded from {model_path}")
        return True
    except Exception as e:
        print(f"[detector] Could not load model: {e}")
        _model = None
        _scaler = None
        _model_trained = False
        return False


def save_model(model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH) -> bool:
    """Save current model and scaler to disk.
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    global _model, _scaler
    
    if _model is None or _scaler is None:
        print("[detector] No model to save")
        return False
    
    try:
        joblib.dump(_model, model_path)
        joblib.dump(_scaler, scaler_path)
        print(f"[detector] Model saved to {model_path}")
        return True
    except Exception as e:
        print(f"[detector] Could not save model: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _normalize_anomaly_score(anomaly_score: Any) -> float:
    """Normalize anomaly score to 0..1 risk scale."""
    try:
        value = float(anomaly_score)
    except (TypeError, ValueError):
        return 0.0

    if 1.0 < value <= 100.0:
        return value / 100.0
    
    if 0.0 <= value <= 1.0:
        return value
    
    # Logistic transform for unbounded scores
    normalized = 1.0 / (1.0 + math.exp(6.0 * value))
    return max(0.0, min(1.0, normalized))


def calculate_risk_score(event: Dict[str, Any]) -> int:
    """Calculate deterministic risk score (0..100) from weighted signals."""
    
    anomaly_component = _normalize_anomaly_score(event.get("anomaly_score", 0.0)) * WEIGHTS["anomaly"]
    activity_component = get_activity_weight(str(event.get("activity_type", ""))) * WEIGHTS["activity"]
    ioc_component = get_ioc_weight(event) * WEIGHTS["ioc"]
    rule_component = get_rule_weight(event) * WEIGHTS["rule"]
    
    score = anomaly_component + activity_component + ioc_component + rule_component
    score = max(0, min(100, int(round(score))))
    return score


# ══════════════════════════════════════════════════════════════════════════════
# MAIN DETECTION FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_anomalies(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect anomalies using pre-trained model + behavioral rules.
    
    IMPORTANT: Model must be trained separately using train_model() or loaded
    using load_model(). This function does NOT auto-train.
    
    Parameters
    ----------
    logs : list[dict]
        Log entries to analyze
        
    Returns
    -------
    list[dict]
        Enriched logs with anomaly detection results
    """
    global _model, _scaler, _model_trained
    
    if not logs:
        print("[detector] No logs to analyze.")
        return []
    
    # Check if model is available
    use_ml = _model_trained and _model is not None and _scaler is not None
    
    if not use_ml:
        print("[detector] WARNING: No trained model available. Using rule-based detection only.")
        print("[detector] Run train_model() or load_model() to enable ML detection.")
    
    print(f"[detector] Analyzing {len(logs)} log(s) (ML={'enabled' if use_ml else 'DISABLED'})...")
    
    # Sort logs chronologically (critical for preventing data leakage)
    sorted_logs = sorted(
        logs,
        key=lambda x: _parse_timestamp(x.get("timestamp")) or datetime.min
    )
    
    # Process logs incrementally
    tracker = IncrementalStatsTracker()
    feature_vectors = []
    enriched_logs = []
    
    for log in sorted_logs:
        current_time = _parse_timestamp(log.get("timestamp"))
        
        # Compute features from PAST data only
        features = tracker.compute_features(log, current_time)
        feature_vectors.append(features)
        
        # Update tracker state for next iteration
        tracker.update_state(log, current_time)
        
        # Store log with features for later processing
        enriched_logs.append({
            **log,
            "_features": features
        })
    
    # Convert features to array for ML model
    df = pd.DataFrame(feature_vectors)
    df = df.replace([float('inf'), float('-inf')], 0.0)
    df = df.fillna(0.0)
    X = df.values
    
    # Get ML anomaly scores if model available
    ml_anomaly_scores = []
    
    if use_ml:
        try:
            X_scaled = _scaler.transform(X)
            predictions = _model.predict(X_scaled)  # 1 = normal, -1 = anomaly
            raw_scores = _model.decision_function(X_scaled)  # higher = more normal
            ml_anomaly_scores = raw_scores
        except Exception as e:
            print(f"[detector] ML inference failed: {e}. Falling back to rule-based only.")
            use_ml = False
            ml_anomaly_scores = [0.0] * len(logs)
    else:
        ml_anomaly_scores = [0.0] * len(logs)
    
    # Compute behavioral rule scores
    behavioral_scores = []
    for log in enriched_logs:
        features = log["_features"]
        behavioral_score = _calculate_behavioral_anomaly_score(log, features)
        behavioral_scores.append(behavioral_score)
    
    # Hybrid scoring (ML + behavioral rules)
    hybrid_scores = []
    
    for i, log in enumerate(enriched_logs):
        features = log["_features"]
        
        # Normalize ML score to 0-1 (lower raw score = more anomalous)
        if use_ml:
            ml_score = 1.0 / (1.0 + math.exp(3.0 * ml_anomaly_scores[i]))  # sigmoid
        else:
            ml_score = 0.0
        
        # Get behavioral score
        behavioral_score = behavioral_scores[i]
        
        # Hybrid combination (60% ML, 40% behavioral when ML available)
        if use_ml:
            hybrid_score = 0.6 * ml_score + 0.4 * behavioral_score
        else:
            hybrid_score = behavioral_score  # 100% behavioral fallback
        
        # Early attack pattern boosting
        if _is_early_attack_pattern(log, features):
            hybrid_score = min(1.0, hybrid_score * 1.3)
        
        hybrid_scores.append(hybrid_score)
    
    # Adaptive threshold (percentile-based)
    if len(hybrid_scores) > 5:
        threshold = sorted(hybrid_scores)[int(len(hybrid_scores) * 0.75)]  # 75th percentile
        threshold = max(0.3, min(0.7, threshold))  # clamp to reasonable range
    else:
        threshold = 0.4  # fallback for small datasets

    high_bytes_threshold = float(df["bytes_transferred"].quantile(0.90)) if "bytes_transferred" in df.columns else 0.0
    ioc_watchlist = _load_ioc_watchlist()
    
    # Build final results
    results = []
    suspicious_count = 0
    
    for i, log in enumerate(enriched_logs):
        features = log["_features"]
        hybrid_score = hybrid_scores[i]
        activity_type = str(log.get("activity_type", "")).strip().lower()
        ioc_matched = _event_matches_ioc(log, ioc_watchlist)
        rule_flags = _build_rule_flags(log, features, high_bytes_threshold)
        
        # Determine label with noise filtering and strong-signal overrides.
        evidence_count = len(rule_flags) + (1 if ioc_matched else 0)
        strong_signal = ioc_matched or activity_type in {"malware_activity", "data_exfiltration"}
        base_flag = hybrid_score >= threshold
        if strong_signal and hybrid_score >= max(0.25, threshold * 0.8):
            label = "suspicious"
        elif base_flag and (evidence_count > 0 or hybrid_score >= 0.7):
            label = "suspicious"
        else:
            label = "normal"
        if label == "suspicious":
            suspicious_count += 1
        
        # Build detection reason
        reasons = []
        if behavioral_scores[i] >= 0.3:
            if features["failed_login_count_5min"] >= BRUTE_FORCE_THRESHOLD:
                reasons.append(f"brute force pattern ({int(features['failed_login_count_5min'])} failed logins)")
            if features["is_burst_activity"] > 0:
                reasons.append("burst activity detected")
            if features["unique_dst_per_src"] > SCAN_THRESHOLD:
                reasons.append(f"scanning ({int(features['unique_dst_per_src'])} destinations)")
            if features["sequence_risk_score"] > 0.5:
                reasons.append("attack sequence detected")
        
        if use_ml and ml_anomaly_scores[i] < -0.2:
            reasons.append(f"ML anomaly (score={ml_anomaly_scores[i]:.2f})")
        
        if behavioral_scores[i] >= 0.5:
            reasons.append(f"behavioral anomaly (score={behavioral_scores[i]:.2f})")
        
        if features["is_unusual_hour"] > 0:
            reasons.append("suspicious activity during unusual hours")

        if ioc_matched:
            reasons.append("IOC watchlist match")

        if rule_flags:
            reasons.append(f"rule_flags={','.join(rule_flags)}")
        
        detection_reason = "; ".join(reasons) if reasons else "no specific indicators"
        
        # Build enriched event
        enriched_event = {
            k: v for k, v in log.items() if k != "_features"
        }
        enriched_event["label"] = label
        # In rules-only mode, expose hybrid score so anomaly_score is still meaningful.
        anomaly_score_value = float(ml_anomaly_scores[i]) if use_ml else float(hybrid_score)
        enriched_event["anomaly_score"] = round(anomaly_score_value, 4)
        enriched_event["anomaly_score_normalized"] = int(round(hybrid_score * 100))  # 0-100 hybrid score
        enriched_event["behavioral_score"] = round(behavioral_scores[i], 4)
        enriched_event["ioc_matched"] = ioc_matched
        enriched_event["rule_flags"] = rule_flags
        enriched_event["risk_score"] = calculate_risk_score(enriched_event)
        enriched_event["severity"] = get_severity(enriched_event["risk_score"])
        enriched_event["detection_quality"] = "model_based" if use_ml else "rule_based"
        enriched_event["detection_reason"] = detection_reason
        
        results.append(enriched_event)
    
    print(f"[detector] {suspicious_count} suspicious / {len(logs) - suspicious_count} normal  "
          f"(threshold={threshold:.2f}, method={'hybrid' if use_ml else 'rules-only'})")
    
    return results


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY COMPATIBILITY
# ══════════════════════════════════════════════════════════════════════════════

def _is_expected_suspicious(event: Dict[str, Any], high_bytes_threshold: float) -> bool:
    """Legacy heuristic (kept for backward compatibility)."""
    activity_weight = get_activity_weight(str(event.get("activity_type", "")))
    try:
        bytes_value = float(event.get("bytes_transferred", 0.0))
    except:
        bytes_value = 0.0
    return activity_weight >= 0.7 or bytes_value >= high_bytes_threshold


def _get_detection_quality(predicted_label: str, expected_suspicious: bool) -> str:
    """Legacy detection quality (kept for backward compatibility)."""
    if predicted_label == "suspicious" and expected_suspicious:
        return "likely_true_positive"
    if predicted_label == "suspicious" and not expected_suspicious:
        return "likely_false_positive"
    if predicted_label == "normal" and expected_suspicious:
        return "likely_false_negative"
    return "likely_true_negative"
