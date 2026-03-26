import time
import re
import requests

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
LOG_FILE      = "fake_hospital_logs.txt"
BACKEND_URL   = "http://localhost:8000/api/logs/ingest"
API_KEY       = "super-secret-key-123"
POLL_INTERVAL = 0.5   # seconds between file-read attempts when idle

HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
}

# Pre-compiled regex matching lines in format:
#   [2026-03-05 17:11:54] [INFO    ] User Dr. Smith logged in from terminal 9
#   Group 1 → timestamp   e.g. "2026-03-05 17:11:54"
#   Group 2 → level       e.g. "INFO    " (stripped below)
#   Group 3 → message     e.g. "User Dr. Smith logged in from terminal 9"
LOG_PATTERN = re.compile(r"^\[(.+?)\]\s+\[(.+?)\]\s+(.+)$")


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def parse_line(line: str) -> dict | None:
    """
    Parse a single log line into a dict with keys:
    timestamp, level, message.
    Returns None if the line doesn't match the expected format.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    return {
        "timestamp": match.group(1).strip(),
        "level":     match.group(2).strip(),
        "message":   match.group(3).strip(),
    }


def send_log(payload: dict) -> None:
    """
    POST the parsed log payload to the FastAPI backend.
    Prints a success message on 200, a warning on any other status,
    and a connection warning if the server is unreachable — but never crashes.
    """
    try:
        response = requests.post(BACKEND_URL, json=payload, headers=HEADERS, timeout=5)

        if response.status_code == 200:
            print(f"  [OK]  Forwarded [{payload['level']}] → {payload['message'][:60]}")
        else:
            print(f"  [WARN] Backend returned {response.status_code}: {response.text[:120]}")

    except requests.exceptions.ConnectionError:
        print(f"  [WARN] Cannot reach backend at {BACKEND_URL} — will retry on next line.")
    except requests.exceptions.Timeout:
        print(f"  [WARN] Request timed out — backend may be overloaded.")
    except requests.exceptions.RequestException as exc:
        print(f"  [WARN] Unexpected request error: {exc}")


def wait_for_file(path: str) -> None:
    """
    Block until the target log file exists.
    Prints a single waiting message so the terminal isn't spammed.
    """
    import os
    if not os.path.exists(path):
        print(f"[AGENT] Waiting for '{path}' to appear...")
        while not os.path.exists(path):
            time.sleep(1)
        print(f"[AGENT] File found — starting tail.")


# ---------------------------------------------------------
# MAIN TAIL LOOP
# ---------------------------------------------------------

def tail_and_forward(path: str) -> None:
    """
    Open the log file and stream new lines as they are written,
    mimicking `tail -f`.  Parses each line and forwards it to the backend.
    """
    wait_for_file(path)

    with open(path, "r", encoding="utf-8") as log_file:
        # Seek to the end so we only process *new* lines written after
        # the agent starts (not the entire historical file).
        log_file.seek(0, 2)
        print(f"[AGENT] Tailing '{path}' — forwarding new lines to {BACKEND_URL}")
        print("-" * 65)

        while True:
            line = log_file.readline()

            if not line:
                # No new data yet — sleep briefly and poll again.
                time.sleep(POLL_INTERVAL)
                continue

            # Skip blank lines silently.
            if not line.strip():
                continue

            payload = parse_line(line)

            if payload is None:
                # Line doesn't match expected format — log and skip.
                print(f"  [SKIP] Unrecognised format: {line.strip()[:80]}")
                continue

            send_log(payload)


# ---------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("  LOG SPY AGENT — File Log Forwarder")
    print("=" * 65)
    try:
        tail_and_forward(LOG_FILE)
    except KeyboardInterrupt:
        print("\n[AGENT] Stopped by user.")
