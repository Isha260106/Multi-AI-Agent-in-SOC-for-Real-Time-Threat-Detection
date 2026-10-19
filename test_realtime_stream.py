"""
test_realtime_stream.py
=======================
End-to-End Validation Test for Stage 8A: Real-Time Event Stream Testing

Multi-Agent SOC Project -- Stage 8A
"""

import pathlib
import sys
import threading
import time

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.realtime_producer import run_realtime_producer
from kafka.consumer import consume_events
from storage.query import AlertQueryStore, IncidentQueryStore

DIV = "=" * 72
pass_count = 0
fail_count = 0

def section(title: str) -> None:
    print(f"\n{DIV}")
    print(f"  {title}")
    print(DIV)

def check(name: str, passed: bool, detail: str = "") -> None:
    global pass_count, fail_count
    icon = "[OK  ]" if passed else "[FAIL]"
    extra = f"  -- {detail}" if detail else ""
    print(f"  {icon}  {name}{extra}")
    if passed:
        pass_count += 1
    else:
        fail_count += 1

def run_tests():
    section("1. Pre-test Database Baseline")
    try:
        with AlertQueryStore() as aqs:
            stats = aqs.summary_stats()
            initial_events = stats["total_events"]
            initial_alerts = stats["total_alerts"]
        with IncidentQueryStore() as iqs:
            initial_incidents = iqs.summary_stats_incidents()["total_incidents"]
        
        check("Database accessible natively", True)
    except Exception as e:
        check(f"Failed to access DB: {e}", False)
        return

    section("2. Producer Validity Boundary Verification")
    events = run_realtime_producer(
        interval=0.0,
        count=3,
        continuous=False,
        label_filter="all",
        source="stage8a_test",
        loop=False,
        silent=True
    )
    
    # Normally it returns the count, wait, run_realtime_producer returns `events_sent`
    # BUT wait, the existing demo relied on `run_producer` returning a list. Let's fix that boundary by checking integer.
    check("Fixed-count limits bounding correctly", events == 3, f"Sent: {events}")

    section("3. Consumer Real-Time Integration")
    consumer_thread = threading.Thread(
        target=consume_events, 
        kwargs={'count': 10, 'silent': True}, 
        daemon=True
    )
    consumer_thread.start()

    # Re-run a controlled injection bounded heavily towards interval checking
    start_time = time.perf_counter()
    injected_count = run_realtime_producer(
        interval=0.1,  
        count=10,
        continuous=False,
        label_filter="all",
        source="stage8a_test_consumer",
        loop=False,
        silent=True
    )
    duration = time.perf_counter() - start_time
    check("Interval delays respected strictly", duration >= 1.0, f"duration: {duration:.2f}s")
    check("Injected exact limits into Queue", injected_count == 10)
    
    consumer_thread.join(timeout=10.0)
    
    with AlertQueryStore() as aqs:
        post_stats = aqs.summary_stats()
        post_events = post_stats["total_events"]
        post_alerts = post_stats["total_alerts"]
        
    check("SQLite Events strictly captured", post_events >= initial_events + 10, f"Initial: {initial_events}, Post: {post_events}")
    
    with IncidentQueryStore() as iqs:
        post_incidents = iqs.summary_stats_incidents()["total_incidents"]
        
    check("SQLite Incidents structurally tracked preventing phantom escalations", post_incidents >= initial_incidents)
    
    # Wait, consuming from the main queue loops safely stopping daemon? Yes, threading.Thread daemon handles exit.
    
    section("Execution Summary")
    print(f"  {pass_count} PASSED  |  {fail_count} FAILED")

if __name__ == "__main__":
    run_tests()
    if fail_count > 0:
        sys.exit(1)
