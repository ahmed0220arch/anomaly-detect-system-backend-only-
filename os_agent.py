import time
import json
import sqlite3
import os
from typing import Dict, List, Tuple

import joblib
import pandas as pd
import psutil
import requests
import yaml

try:
    import win32evtlog
except ImportError as exc:
    raise SystemExit(
        "pywin32 is required for os_agent.py. Install it with: pip install pywin32"
    ) from exc

import re

# =========================================================
# HEURISTIC PRE-FILTER
# Purpose: Drop known-legitimate Windows system noise BEFORE
#          it reaches the ML model. This reduces false positives
#          and keeps the database clean.
#
# SAFETY: If a log LOOKS like system noise but has a suspicious
#         path or arguments, it is NOT dropped — it goes straight
#         to the ML model for anomaly scoring.
#
# THIS DOES NOT TOUCH: ml_service.py, main.py, or the ML model.
# =========================================================

# Legitimate WidgetService path regex (Microsoft Store app)
_WIDGET_SERVICE_LEGIT_PATH = re.compile(
    r"C:\\Program Files\\WindowsApps\\Microsoft\.WidgetsPlatformRuntime_[^\\]+_x64__8wekyb3d8bbwe\\WidgetService\\WidgetService\.exe",
    re.IGNORECASE,
)
_WIDGET_SERVICE_LEGIT_ARGS = "-RegisterProcessAsComServer -Embedding"

# Suspicious paths that malware uses to disguise as system processes
_SUSPICIOUS_PATHS = re.compile(
    r"(C:\\Temp|\\AppData\\|C:\\Users\\[^\\]+\\Downloads|C:\\ProgramData\\(?!Microsoft))",
    re.IGNORECASE,
)

# Known safe Windows Security audit patterns (AUTORITE NT / SYSTEM logons)
_SAFE_SYSTEM_LOGON = re.compile(
    r"S-1-5-18\s*\|.*(?:AUTORITE NT|NT AUTHORITY).*\|.*0x3e7",
    re.IGNORECASE,
)
_SAFE_PRIVILEGE_ASSIGN = re.compile(
    r"S-1-5-18\s*\|.*(?:Système|SYSTEM).*\|.*Se\w+Privilege",
    re.IGNORECASE,
)
_SAFE_SERVICES_EXE_LOGON = re.compile(
    r"C:\\Windows\\System32\\services\.exe.*%%1833",
    re.IGNORECASE,
)


def is_known_noise(message: str, source_name: str) -> bool:
    """
    Returns True if the log is known-legitimate Windows noise
    that should be DROPPED (not sent to ML).
    
    Returns False if the log should be SENT to ML for scoring.
    """
    text = message or ""
    
    # --- WidgetService Heuristic ---
    if "WidgetService" in text or "WidgetService" in source_name:
        # Check if it's the REAL Microsoft WidgetService
        has_legit_path = bool(_WIDGET_SERVICE_LEGIT_PATH.search(text))
        has_legit_args = _WIDGET_SERVICE_LEGIT_ARGS in text
        has_suspicious_path = bool(_SUSPICIOUS_PATHS.search(text))
        
        if has_legit_path and has_legit_args and not has_suspicious_path:
            return True  # Safe: drop it
        else:
            return False  # Suspicious variant: SEND TO ML!
    
    # --- Windows SYSTEM Account Routine Audit Logs ---
    # These are standard privilege assignments and logon events
    # from the NT AUTHORITY\SYSTEM account (S-1-5-18)
    if _SAFE_SYSTEM_LOGON.search(text):
        # Make sure it's not coming from a suspicious path
        if _SUSPICIOUS_PATHS.search(text):
            return False  # Suspicious: SEND TO ML!
        
        # Check for standard privilege assignment patterns
        if _SAFE_PRIVILEGE_ASSIGN.search(text):
            return True  # Safe routine privilege assignment
        
        # Check for standard services.exe logon patterns 
        if _SAFE_SERVICES_EXE_LOGON.search(text):
            return True  # Safe routine SYSTEM logon via services.exe
    
    # Not recognized as noise — send to ML
    return False


TARGET_LOGS = ["Application", "System", "Security"]

# Configuration will be loaded from logagent.yaml
BACKEND_URL: str = ""
API_KEY: str = ""
BATCH_SIZE: int = 100
POLL_INTERVAL_SECONDS: int = 10
FLUSH_INTERVAL_SECONDS: int = 60
SQLITE_DB_PATH: str = "local_buffer.db"
HEADERS: Dict[str, str] = {}


def load_config(config_path: str = "logagent.yaml") -> None:
    """Load configuration from logagent.yaml file.
    
    Expected YAML structure:
    server_url: "http://localhost:8000/api/logs/ingest"
    api_key: "your-secret-key"
    batch_size: 100
    poll_interval_seconds: 10
    flush_interval_seconds: 60
    sqlite_db_path: "local_buffer.db"
    """
    global BACKEND_URL, API_KEY, BATCH_SIZE, POLL_INTERVAL_SECONDS, FLUSH_INTERVAL_SECONDS, SQLITE_DB_PATH, HEADERS
    
    if not os.path.exists(config_path):
        default_yaml = '''# Default logagent.yaml
server_url: "http://localhost:8000/api/logs/ingest"
api_key: "PUT_VALID_PROJECT_API_KEY_HERE"
batch_size: 10
poll_interval_seconds: 5
flush_interval_seconds: 30
sqlite_db_path: "local_buffer.db"
'''
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(default_yaml)
        raise SystemExit(
            f"[CRITICAL] Config file '{config_path}' not found. A default has been created. "
            f"Please edit it to include a valid 'api_key' and restart."
        )
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        raise SystemExit(
            f"[CRITICAL] Failed to load config file '{config_path}': {exc}"
        ) from exc
    
    if not isinstance(config, dict):
        raise SystemExit(
            f"[CRITICAL] Config file '{config_path}' must contain a YAML dictionary."
        )
    
    # Extract required keys with fallback to defaults where sensible
    try:
        BACKEND_URL = config.get("server_url", "http://localhost:8000/api/logs/ingest")
        api_key_value = config.get("api_key")
        if not api_key_value:
            raise SystemExit(
                "[CRITICAL] Missing required config key: api_key"
            )
        API_KEY = str(api_key_value)
        
        BATCH_SIZE = config.get("batch_size", 100)
        POLL_INTERVAL_SECONDS = config.get("poll_interval_seconds", 10)
        FLUSH_INTERVAL_SECONDS = config.get("flush_interval_seconds", 60)
        SQLITE_DB_PATH = config.get("sqlite_db_path", "local_buffer.db")
        
        HEADERS = {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        }
        
        print(f"[CONFIG] Loaded configuration from '{config_path}'")
        print(f"[CONFIG] Backend URL: {BACKEND_URL}")
        print(f"[CONFIG] Batch size: {BATCH_SIZE}")
        print(f"[CONFIG] Poll interval: {POLL_INTERVAL_SECONDS}s")
        print(f"[CONFIG] Buffer DB: {SQLITE_DB_PATH}")
    except KeyError as exc:
        raise SystemExit(
            f"[CRITICAL] Missing required config key: {exc}"
        ) from exc

EVENT_TYPE_MAP = {
    win32evtlog.EVENTLOG_ERROR_TYPE: "ERROR",
    win32evtlog.EVENTLOG_WARNING_TYPE: "WARNING",
    win32evtlog.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32evtlog.EVENTLOG_AUDIT_SUCCESS: "INFO",
    win32evtlog.EVENTLOG_AUDIT_FAILURE: "WARNING",
}


def init_local_buffer_db() -> None:
    """Create the local SQLite buffer if it does not exist."""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs_buffer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_payloads_to_local_buffer(payloads: List[Dict[str, object]]) -> None:
    """Persist payloads locally for retry when backend is unavailable."""
    if not payloads:
        return

    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        rows = [(json.dumps(payload),) for payload in payloads]
        conn.executemany("INSERT INTO logs_buffer(payload_json) VALUES (?)", rows)
        conn.commit()
    finally:
        conn.close()

    print(f"[WARN] Buffered {len(payloads)} logs in local SQLite store")


def read_buffered_payloads() -> Tuple[List[int], List[Dict[str, object]]]:
    """Read buffered payloads from SQLite ordered by insertion id."""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        rows = conn.execute(
            "SELECT id, payload_json FROM logs_buffer ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    ids: List[int] = []
    payloads: List[Dict[str, object]] = []
    for row_id, payload_json in rows:
        try:
            parsed = json.loads(payload_json)
            if isinstance(parsed, dict):
                ids.append(int(row_id))
                payloads.append(parsed)
        except json.JSONDecodeError:
            print(f"[WARN] Skipping corrupted buffered payload id={row_id}")

    return ids, payloads


def delete_buffered_payloads(ids: List[int]) -> None:
    """Delete successfully replayed buffered payloads from SQLite."""
    if not ids:
        return

    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        conn.executemany("DELETE FROM logs_buffer WHERE id = ?", [(row_id,) for row_id in ids])
        conn.commit()
    finally:
        conn.close()


def post_batch(payloads: List[Dict[str, object]]) -> bool:
    """Send one batch payload (JSON array) to the FastAPI ingest endpoint."""
    if not payloads:
        return True

    try:
        response = requests.post(BACKEND_URL, json=payloads, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            print(f"[OK] Sent batch of {len(payloads)} logs")
            return True
        else:
            print(
                f"[WARN] Backend response {response.status_code}: {response.text[:120]}"
            )
            return False
    except requests.exceptions.RequestException as exc:
        print(f"[WARN] Could not send batch to backend: {exc}")
        return False


def replay_local_buffer() -> bool:
    """
    Try sending buffered payloads from SQLite first.
    Returns True if buffer is empty or replay succeeded, False otherwise.
    """
    ids, payloads = read_buffered_payloads()
    if not payloads:
        return True

    print(f"[AGENT] Attempting replay of {len(payloads)} buffered logs")
    if post_batch(payloads):
        delete_buffered_payloads(ids)
        print(f"[OK] Replayed and deleted {len(payloads)} buffered logs")
        return True

    print("[WARN] Replay failed; keeping buffered logs for later retry")
    return False


def get_latest_record_number(log_name: str) -> int:
    """Return the latest record number currently present in a Windows event log."""
    handle = win32evtlog.OpenEventLog(None, log_name)
    try:
        # pywin32 APIs are dynamically typed; cast to int to avoid linter/type issues.
        oldest = int(win32evtlog.GetOldestEventLogRecord(handle))
        total = int(win32evtlog.GetNumberOfEventLogRecords(handle))
        if total <= 0:
            return oldest
        return oldest + total - 1
    finally:
        win32evtlog.CloseEventLog(handle)


def load_ml_pipeline() -> Tuple[object, object]:
    """Load translator and brain models from files next to this script."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    translator_path = os.path.join(script_dir, "translator.pkl")
    brain_path = os.path.join(script_dir, "smart_agent_brain.pkl")

    if not os.path.exists(translator_path) or not os.path.exists(brain_path):
        print(f"[WARN] Missing ML model files: {translator_path} or {brain_path}")
        print("[WARN] Agent will run in fallback mode without ML anomaly detection.")
        return None, None

    translator = joblib.load(translator_path)
    brain = joblib.load(brain_path)
    print("[ML] Loaded translator.pkl and smart_agent_brain.pkl")
    return translator, brain


def read_new_events(log_name: str, last_record: int, translator: object, brain: object) -> Tuple[List[dict], int]:
    """
    Read only events newer than last_record from the given log.
    Returns (payloads_to_send, new_last_record).
    """
    handle = win32evtlog.OpenEventLog(None, log_name)
    payloads: List[dict] = []
    new_last_record = last_record

    try:
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, last_record + 1)

        while events:
            for event in events:
                record_number = int(event.RecordNumber)
                if record_number <= new_last_record:
                    continue

                # Always move cursor forward so we never resend duplicates.
                new_last_record = record_number

                # Keep every event type. Unknown types are treated as INFO.
                level = EVENT_TYPE_MAP.get(event.EventType, "INFO")

                inserts = event.StringInserts or []
                message = " | ".join(str(part) for part in inserts).strip()
                if not message:
                    message = f"EventID={event.EventID} Source={event.SourceName}"

                source_name = str(event.SourceName or log_name)

                # ---- HEURISTIC PRE-FILTER ----
                # Drop known-legitimate Windows noise before it hits ML
                if is_known_noise(message, source_name):
                    print(
                        f"NOISE FILTERED | {log_name}: {source_name} (dropped before ML)"
                    )
                    continue  # Skip this log entirely
                # ---- END PRE-FILTER ----

                event_df = pd.DataFrame(
                    [
                        {
                            "Nível": level,
                            "Fonte": source_name,
                            "Description1": message,
                        }
                    ]
                )
                try:
                    if translator is None or brain is None:
                        anomaly_score = 0.0
                    else:
                        translated = translator.transform(event_df)
                        anomaly_score = float(brain.decision_function(translated)[0])
                except Exception as exc:
                    print(
                        f"[WARN] ML inference failed for {log_name} record {record_number}: {exc}"
                    )
                    # Safe fallback: unknown/unfamiliar logs should not crash the agent loop.
                    anomaly_score = 0.0

                if anomaly_score >= 0:
                    print(
                        f"NORMAL | score={anomaly_score:.4f} | {log_name}: {source_name}"
                    )
                elif anomaly_score > -0.15:
                    print(
                        f"MINOR WARNING: Ignoring... | score={anomaly_score:.4f} | {log_name}: {source_name}"
                    )
                else:
                    print(
                        f"CRITICAL ANOMALY DETECTED! | score={anomaly_score:.4f} | {log_name}: {source_name} | {message}"
                    )

                payloads.append(
                    {
                        "timestamp": str(event.TimeGenerated),
                        "level": level,
                        "source": source_name,
                        "message": message,
                        "anomaly_score": anomaly_score,
                    }
                )

            events = win32evtlog.ReadEventLog(handle, flags, 0)

    finally:
        win32evtlog.CloseEventLog(handle)

    return payloads, new_last_record


def main() -> None:
    load_config()
    init_local_buffer_db()
    translator, brain = load_ml_pipeline()

    while True:
        try:
            # Initialize cursors at current tail so agent streams only future events.
            last_seen: Dict[str, int] = {}
            pending_payloads: List[Dict[str, object]] = []
            last_flush = time.monotonic()
            for log_name in TARGET_LOGS:
                try:
                    last_seen[log_name] = get_latest_record_number(log_name)
                    print(f"[INIT] {log_name} cursor at record {last_seen[log_name]}")
                except Exception as exc:
                    last_seen[log_name] = 0
                    print(f"[WARN] Could not initialize {log_name} log cursor: {exc}")

            print(
                "[AGENT] Monitoring Windows Application/System/Security logs for all levels..."
            )

            while True:
                # Sample CPU and RAM once per polling cycle.
                # Because there is a time.sleep() at the end of the loop,
                # this returns the actual CPU usage over that sleep interval.
                current_cpu = psutil.cpu_percent()
                current_ram = psutil.virtual_memory().percent

                replay_ok = replay_local_buffer()

                for log_name in TARGET_LOGS:
                    try:
                        payloads, new_last = read_new_events(
                            log_name,
                            last_seen[log_name],
                            translator,
                            brain,
                        )
                        last_seen[log_name] = new_last

                        for payload in payloads:
                            payload["cpu_percent"] = current_cpu
                            payload["ram_percent"] = current_ram
                            pending_payloads.append(payload)

                    except Exception as exc:
                        print(f"[WARN] Failed to read {log_name} event log: {exc}")

                elapsed = time.monotonic() - last_flush
                should_flush = len(pending_payloads) >= BATCH_SIZE or (
                    pending_payloads and elapsed >= FLUSH_INTERVAL_SECONDS
                )

                if should_flush:
                    if replay_ok and post_batch(pending_payloads):
                        pending_payloads.clear()
                    else:
                        insert_payloads_to_local_buffer(pending_payloads)
                        pending_payloads.clear()

                    last_flush = time.monotonic()

                time.sleep(POLL_INTERVAL_SECONDS)

        except Exception as e:
            print(f"[CRITICAL] Agent crashed, rebooting in 5 seconds: {e}")
            time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[AGENT] Stopped by user.")
