import argparse
import json
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import psutil
import requests
from sqlalchemy import create_engine, text


def get_api_key_from_db(database_url: str) -> tuple[int, str]:
	engine = create_engine(database_url)
	with engine.connect() as conn:
		row = conn.execute(text("SELECT id, api_key FROM projects ORDER BY id ASC LIMIT 1")).fetchone()
		if row is not None:
			return int(row[0]), str(row[1])

		conn.execute(
			text(
				"""
				INSERT INTO projects (name, description, is_active, api_key, created_at)
				VALUES (:name, :description, :is_active, :api_key, NOW())
				RETURNING id, api_key
				"""
			),
			{
				"name": "Stress Test Project",
				"description": "Auto-created for burst test",
				"is_active": True,
				"api_key": "stress_test_static_key_001",
			},
		)
		conn.commit()
		row = conn.execute(text("SELECT id, api_key FROM projects ORDER BY id ASC LIMIT 1")).fetchone()
		return int(row[0]), str(row[1])


def percentile(values: list[float], p: float) -> float:
	if not values:
		return 0.0
	ordered = sorted(values)
	k = (len(ordered) - 1) * p
	f = int(k)
	c = min(f + 1, len(ordered) - 1)
	if f == c:
		return ordered[f]
	return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def main() -> None:
	parser = argparse.ArgumentParser()
	parser.add_argument("--base-url", default="http://127.0.0.1:8000")
	parser.add_argument("--database-url", default="postgresql://postgres:admin@localhost/pfe_project")
	parser.add_argument("--count", type=int, default=1000)
	parser.add_argument("--workers", type=int, default=220)
	parser.add_argument("--drain-seconds", type=int, default=20)
	parser.add_argument("--pid", type=int, required=True)
	args = parser.parse_args()

	project_id, api_key = get_api_key_from_db(args.database_url)

	proc = psutil.Process(args.pid)
	proc.cpu_percent(interval=None)

	samples: list[dict] = []
	stop_evt = threading.Event()

	def monitor() -> None:
		while not stop_evt.is_set():
			try:
				samples.append(
					{
						"rss_mb": proc.memory_info().rss / (1024 * 1024),
						"cpu": proc.cpu_percent(interval=None),
						"t": time.time(),
					}
				)
			except Exception:
				pass
			time.sleep(0.1)

	monitor_thread = threading.Thread(target=monitor, daemon=True)
	monitor_thread.start()

	start_evt = threading.Event()

	def send_one(idx: int) -> dict:
		start_evt.wait()
		payload = {
			"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
			"level": "INFO",
			"message": f"EMERGENCY-RUSH INFO #{idx}",
			"cpu_percent": 21.3,
			"ram_percent": 48.7,
		}
		headers = {"X-API-Key": api_key}
		t0 = time.perf_counter()
		try:
			response = requests.post(
				f"{args.base_url}/api/logs/ingest",
				headers=headers,
				json=payload,
				timeout=20,
			)
			latency_ms = (time.perf_counter() - t0) * 1000.0
			ok = response.status_code == 200 and response.json().get("status") == "success"
			return {"ok": ok, "latency_ms": latency_ms, "status_code": response.status_code}
		except Exception as exc:
			latency_ms = (time.perf_counter() - t0) * 1000.0
			return {"ok": False, "latency_ms": latency_ms, "status_code": None, "error": str(exc)[:120]}

	burst_start = time.perf_counter()
	with ThreadPoolExecutor(max_workers=args.workers) as pool:
		futures = [pool.submit(send_one, i) for i in range(args.count)]
		start_evt.set()
		results = [f.result() for f in as_completed(futures)]
	burst_elapsed = time.perf_counter() - burst_start

	time.sleep(args.drain_seconds)
	stop_evt.set()
	monitor_thread.join(timeout=2)

	latencies = [x["latency_ms"] for x in results]
	successes = [x for x in results if x["ok"]]
	failures = [x for x in results if not x["ok"]]

	rss = [s["rss_mb"] for s in samples] if samples else [0.0]
	cpu = [s["cpu"] for s in samples] if samples else [0.0]

	report = {
		"count_sent": args.count,
		"workers": args.workers,
		"project_id": project_id,
		"burst_elapsed_s": round(burst_elapsed, 3),
		"throughput_req_per_s": round(args.count / burst_elapsed, 2) if burst_elapsed > 0 else 0.0,
		"success_count": len(successes),
		"failure_count": len(failures),
		"http_latency_ms": {
			"avg": round(statistics.fmean(latencies), 2) if latencies else 0.0,
			"p50": round(percentile(latencies, 0.50), 2) if latencies else 0.0,
			"p95": round(percentile(latencies, 0.95), 2) if latencies else 0.0,
			"p99": round(percentile(latencies, 0.99), 2) if latencies else 0.0,
			"max": round(max(latencies), 2) if latencies else 0.0,
		},
		"backend_process": {
			"pid": args.pid,
			"rss_mb": {
				"min": round(min(rss), 2),
				"max": round(max(rss), 2),
				"delta": round(max(rss) - min(rss), 2),
			},
			"cpu_percent": {
				"avg": round(statistics.fmean(cpu), 2) if cpu else 0.0,
				"max": round(max(cpu), 2) if cpu else 0.0,
			},
			"sample_count": len(samples),
			"monitor_window_s": args.drain_seconds,
		},
		"error_examples": [x.get("error", x.get("status_code")) for x in failures[:5]],
	}

	with open("burst_benchmark_report.json", "w", encoding="utf-8") as fp:
		json.dump(report, fp, indent=2)

	print(json.dumps(report, indent=2))


if __name__ == "__main__":
	main()