"""
kafka/realtime_producer.py
==========================
Continuous real-time event-stream simulator.

Multi-Agent SOC Project -- Stage 8A
"""

import argparse
import logging
import pathlib
import sys
import time

import pandas as pd

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.config import (
    DATASET_PATH,
    DEFAULT_TRANSPORT,
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC,
    LABEL_COLUMN,
    CSV_CHUNK_SIZE,
)
from kafka.producer import build_event, _log
from kafka.stream import make_producer


def _stream_dataset_rows(dataset_path: pathlib.Path, label_filter: str, loop: bool):
    """
    Generator that sequentially yields rows from the dataset.
    If loop is True, restarts from the beginning when it reaches the end.
    Yields indefinitely until manually broken.
    """
    while True:
        for chunk in pd.read_csv(dataset_path, chunksize=CSV_CHUNK_SIZE, low_memory=False):
            if label_filter != "all" and LABEL_COLUMN in chunk.columns:
                target = "Benign" if label_filter == "benign" else "Infilteration"
                chunk = chunk[chunk[LABEL_COLUMN] == target]
            
            rows = chunk.to_dict(orient="records")
            for row in rows:
                yield row
        
        if not loop:
            break


def run_realtime_producer(
    interval: float,
    count: int | None,
    continuous: bool,
    label_filter: str,
    source: str,
    loop: bool,
    transport: str = DEFAULT_TRANSPORT,
    topic: str = KAFKA_TOPIC,
    bootstrap_servers: str = KAFKA_BOOTSTRAP_SERVERS,
    feature_names: list | None = None,
    silent: bool = False,
) -> int:
    def pr(*args, **kwargs):
        if not silent:
            print(*args, **kwargs)

    try:
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        ANSI = True
    except Exception:
        ANSI = False

    GREEN  = "\033[92m" if ANSI else ""
    YELLOW = "\033[93m" if ANSI else ""
    BOLD   = "\033[1m"  if ANSI else ""
    RESET  = "\033[0m"  if ANSI else ""

    if feature_names is None:
        import joblib
        from kafka.config import PREP_PATH
        if not PREP_PATH.exists():
            raise FileNotFoundError("Preprocessing metadata not found. Ensure Stage 3 is complete.")
        prep = joblib.load(PREP_PATH)
        feature_names = prep["feature_names"]

    if interval < 0:
        raise ValueError("Interval cannot be negative.")
    if count is not None and count <= 0:
        raise ValueError("Count must be greater than zero if specified.")
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")
    if label_filter not in ["all", "benign", "attack"]:
        raise ValueError(f"Invalid label filter: {label_filter}")

    _log.info("Real-Time Producer started. interval=%s count=%s loop=%s label=%s",
              interval, count, loop, label_filter)

    pr(f"\n{BOLD}=== CONTINUOUS EVENT-STREAM SIMULATOR ==={RESET}")
    pr(f"  Mode     : {'Continuous' if continuous else f'Fixed count ({count})'}")
    pr(f"  Interval : {interval} sec")
    pr(f"  Filter   : {label_filter}")
    pr(f"  Looping  : {loop}")
    pr(f"  Source   : {source}")
    pr(f"  Transport: {transport.upper()}")
    pr()
    
    producer = make_producer(transport, topic, bootstrap_servers)
    iterator = _stream_dataset_rows(DATASET_PATH, label_filter, loop)
    
    events_sent = 0
    t_start = time.perf_counter()

    try:
        for row in iterator:
            if not continuous and count is not None and events_sent >= count:
                break
                
            sequence = events_sent + 1
            event = build_event(row, feature_names, sequence)
            event["source"] = source
            
            producer.send(event)
            events_sent += 1
            
            label_info = f"Actual={event.get('actual_label', 'none')}"
            pr(f"  {GREEN}[Producer]{RESET} Event {sequence} sent | ID: {event['event_id'][:8]}... | {label_info}")
            
            if interval > 0:
                time.sleep(interval)
                
    except KeyboardInterrupt:
        pr(f"\n  {YELLOW}[Producer] Stopped gracefully by user (Ctrl+C).{RESET}")
    finally:
        producer.flush()
        producer.close()
        
    t_elapsed = time.perf_counter() - t_start
    pr(f"\n  {BOLD}Simulation Finished.{RESET}")
    pr(f"  Sent       : {events_sent} events")
    if events_sent > 0:
        avg_ms = (t_elapsed / events_sent) * 1000
        pr(f"  Avg process: {avg_ms:.2f} ms / event (including interval waits locally)")
        
    return events_sent


def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Real-Time Event Stream Simulator (Stage 8A)\n"
            "Emits sequential dataset records to a streaming payload queue."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--interval", type=float, default=1.0,
                   help="Delay between events in seconds. Default: 1.0")
    p.add_argument("--count", type=int, default=None,
                   help="Number of events to send.")
    p.add_argument("--continuous", action="store_true", default=False,
                   help="Continuously replay events until Ctrl+C.")
    p.add_argument("--label", type=str, choices=["all", "benign", "attack"], default="all",
                   help="Filter dataset records exclusively.")
    p.add_argument("--source", type=str, default="realtime_dataset_replay",
                   help="Source identification tag injected into events.")
    p.add_argument("--loop", action="store_true", default=False,
                   help="Loop dataset sequentially upon reaching EOF.")
    
    args = p.parse_args()
    
    if args.count is None and not args.continuous:
        # Default behavior context parsing if neither was strictly provided
        args.count = 20
        args.continuous = False

    return args


if __name__ == "__main__":
    args = _parse_args()
    try:
        run_realtime_producer(
            interval=args.interval,
            count=args.count,
            continuous=args.continuous,
            label_filter=args.label,
            source=args.source,
            loop=args.loop
        )
    except Exception as exc:
        print(f"\n[FATAL] Producer Error: {exc}")
        sys.exit(1)
