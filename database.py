from typing import Any, Dict, List, Optional
from datetime import datetime

from pymongo import MongoClient
from pymongo.database import Database
from bson import ObjectId

# ================== CONFIG ==================
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "proshield_ai")


_client: Optional[MongoClient] = None
_db: Optional[Database] = None


# ================== CONNECTION ==================
def connect() -> bool:
    global _client, _db

    if _client is not None and _db is not None:
        return True  # already connected

    if _client is not None and _db is None:
        try:
            _db = _client[DB_NAME]
            return True
        except Exception:
            _client = None
            _db = None

    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        _client.server_info()
        _db = _client[DB_NAME]
        print(f"[database] Connected to MongoDB -> {DB_NAME}")
        return True
    except Exception as e:
        print(f"[database] Connection failed: {e}")
        _client = None
        _db = None
        return False


def _get_collection(name: str):
    if _db is None:
        print("[database] Not connected. Call connect() first.")
        return None
    return _db[name]


# ================== HELPERS ==================
def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, ObjectId):
        return str(value)
    return value


def _serialize(docs):
    return [_sanitize(doc) for doc in docs]


def _insert_one(collection, data):
    col = _get_collection(collection)
    if col is None:
        return None
    result = col.insert_one(data)
    return str(result.inserted_id)


def _get_all(collection):
    col = _get_collection(collection)
    if col is None:
        return []
    return _serialize(list(col.find()))


# ================== USERS ==================
def create_user(email: str, password: str) -> Dict:
    if not connect():
        return {"success": False}

    col = _get_collection("users")
    if col is None:
        return {"success": False, "message": "Database connection failed"}

    col.create_index("email", unique=True)

    if col.find_one({"email": email}):
        return {"success": False, "message": "User exists"}

    _insert_one("users", {
        "email": email,
        "password": password
    })

    return {"success": True}


def get_user(email: str) -> Optional[Dict]:
    if not connect():
        return None

    col = _get_collection("users")
    if col is None:
        return None

    user = col.find_one({"email": email})

    return _sanitize(user) if user else None


# ================== LOGS ==================
def save_log(log: Dict):
    return _insert_one("logs", log)


def get_logs():
    return _get_all("logs")


# ================== EVENTS ==================
def save_event(event: Dict):
    return _insert_one("events", event)


def get_events():
    col = _get_collection("events")
    if col is None:
        return []
    return _serialize(list(col.find().sort("_id", -1)))


# ================== INCIDENTS ==================
def save_incident(data: Dict):
    return _insert_one("incidents", data)


def get_incidents():
    return _get_all("incidents")


# ================== ATTACKERS ==================
def save_attacker(data: Dict):
    return _insert_one("attackers", data)


def get_attackers():
    return _get_all("attackers")


# ================== REPORTS ==================
def save_report(data: Dict):
    return _insert_one("reports", data)


def get_reports():
    return _get_all("reports")