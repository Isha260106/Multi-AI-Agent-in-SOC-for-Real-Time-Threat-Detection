#!/usr/bin/env python3
"""
Multi-Agent SOC Lab: Benign Traffic Generator
Executed on Attacker VM (10.10.10.100) targeting Victim VM (10.10.10.20)
Generates normal HTTP GET and POST requests with natural inter-arrival times
and graceful TCP session teardown to establish baseline benign network flows.
"""

import argparse
import random
import sys
import time
import urllib.parse
import urllib.request

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

ENDPOINTS = [
    ("/", "GET", None),
    ("/index.html", "GET", None),
    ("/api/health", "GET", None),
    ("/api/test", "POST", b'{"action":"ping","timestamp":"now"}'),
]


def send_request(url: str, method: str, data: bytes | None) -> int:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Connection": "close",  # Force clean TCP FIN to produce bounded flows
    }
    if data and method == "POST":
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status
    except Exception as exc:
        return getattr(exc, "code", 500)


def main():
    parser = argparse.ArgumentParser(description="SOC Lab Benign Traffic Generator")
    parser.add_argument("--target-ip", default="10.10.10.20", help="Victim IP address (default: 10.10.10.20)")
    parser.add_argument("--port", type=int, default=80, help="Victim HTTP port (default: 80)")
    parser.add_argument("--duration-sec", type=int, default=60, help="Test run duration in seconds (default: 60)")
    parser.add_argument("--requests-per-min", type=int, default=60, help="Target request rate (default: 60)")
    args = parser.parse_args()

    base_url = f"http://{args.target_ip}:{args.port}"
    mean_delay = 60.0 / max(1, args.requests_per_min)
    end_time = time.time() + args.duration_sec

    print(f"[*] Starting Benign Traffic Generator -> {base_url}")
    print(f"[*] Duration: {args.duration_sec}s | Rate: ~{args.requests_per_min} req/min (mean delay: {mean_delay:.2f}s)")

    sent = 0
    status_counts = {}

    try:
        while time.time() < end_time:
            path, method, payload = random.choice(ENDPOINTS)
            target_url = f"{base_url}{path}"

            status = send_request(target_url, method, payload)
            sent += 1
            status_counts[status] = status_counts.get(status, 0) + 1

            if sent % 10 == 0:
                print(f"    [+] Sent: {sent} requests | Last status: {status} | Statuses: {status_counts}")

            # Natural delay with small jitter
            jitter = random.uniform(0.5, 1.5)
            time.sleep(max(0.1, mean_delay * jitter))

    except KeyboardInterrupt:
        print("\n[!] Generator interrupted by user.")

    print("\n[=] Benign Traffic Run Completed:")
    print(f"    Total Requests Sent: {sent}")
    print(f"    Status Code Breakdown: {status_counts}")


if __name__ == "__main__":
    main()
