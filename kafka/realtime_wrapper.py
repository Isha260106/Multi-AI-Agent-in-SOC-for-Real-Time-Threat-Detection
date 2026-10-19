import argparse
import sys
import pathlib
import threading
import time
import sqlite3

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Wait for consumer to be ready before firing events locally
from kafka.consumer import consume_events
from kafka.realtime_producer import run_realtime_producer
from storage.config import DB_PATH

def print_demonstration_summary(start_event_id, start_time):
    runtime = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("STAGE 8B — SOC DEMONSTRATION SUMMARY")
    print("=" * 60 + "\n")
    
    if not DB_PATH.exists():
        print("Error: Database not found. Cannot print summary.")
        return
        
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            
            # Events processed in this run
            cur = conn.execute("SELECT COUNT(*), strftime('%s', MAX(ingested_at)) - strftime('%s', MIN(ingested_at)) FROM events WHERE id > ?", (start_event_id,))
            row = cur.fetchone()
            events_processed = row[0] if row else 0
            
            if events_processed == 0:
                print("Events Processed : 0\n")
                print("============================================================")
                print("SOC STREAM STOPPED")
                print("============================================================")
                return

            print(f"Events Processed : {events_processed}\n")
            
            # Network Predictions
            cur = conn.execute("""
                SELECT prediction, COUNT(*) FROM alerts 
                WHERE event_id IN (SELECT event_id FROM events WHERE id > ?) 
                AND agent = 'Network Detection Agent'
                GROUP BY prediction
            """, (start_event_id,))
            network_preds = {r[0]: r[1] for r in cur.fetchall()}
            
            benign = network_preds.get('Benign', 0)
            attack = network_preds.get('Infilteration', 0)
            
            print("Network Predictions")
            print(f"  Benign         : {benign}")
            print(f"  Attack         : {attack}\n")
            
            # Anomaly Results
            cur = conn.execute("""
                SELECT prediction, COUNT(*) FROM alerts 
                WHERE event_id IN (SELECT event_id FROM events WHERE id > ?) 
                AND agent = 'Anomaly Detection Agent'
                GROUP BY prediction
            """, (start_event_id,))
            anomaly_preds = {r[0]: r[1] for r in cur.fetchall()}
            
            normal = anomaly_preds.get('Normal', 0)
            anomalous = anomaly_preds.get('Anomalous', 0)
            
            print("Anomaly Results")
            print(f"  Normal         : {normal}")
            print(f"  Anomalous      : {anomalous}\n")
            
            # Alerts generated -> Count of alerts above LOW severity, or just basic alerts? 
            # The assignment just says "Alerts Generated". We'll count what's in alerts for this run, 
            # or maybe just all alerts not NORMAL. Or literally COUNT(*). 
            # We'll stick to severity > LOW as per standard alerting, or just count all alerts.
            # Actually, the pipeline has alerts generated based on the model.
            cur = conn.execute("SELECT COUNT(*) FROM alerts WHERE event_id IN (SELECT event_id FROM events WHERE id > ?)", (start_event_id,))
            alerts_all = cur.fetchone()[0]
            
            # Incidents created
            cur = conn.execute("SELECT COUNT(*) FROM incidents WHERE event_id IN (SELECT event_id FROM events WHERE id > ?)", (start_event_id,))
            incidents = cur.fetchone()[0]
            
            print(f"Alerts Generated : {alerts_all}")
            print(f"Incidents Created: {incidents}\n")
            
            # Processing Latency (we calculate from all alerts or network alerts of this event set)
            cur = conn.execute("""
                SELECT AVG(processing_time_s), MIN(processing_time_s), MAX(processing_time_s) 
                FROM alerts 
                WHERE event_id IN (SELECT event_id FROM events WHERE id > ?)
                AND agent = 'Network Detection Agent'
                AND processing_time_s IS NOT NULL
            """, (start_event_id,))
            lat_row = cur.fetchone()
            avg_lat = (lat_row[0] * 1000) if lat_row and lat_row[0] else 0.0
            min_lat = (lat_row[1] * 1000) if lat_row and lat_row[1] else 0.0
            max_lat = (lat_row[2] * 1000) if lat_row and lat_row[2] else 0.0
            
            print("Processing Latency")
            if lat_row and lat_row[0] is not None:
                print(f"  Average        : {avg_lat:.1f} ms")
                print(f"  Minimum        : {min_lat:.0f} ms")
                print(f"  Maximum        : {max_lat:.0f} ms\n")
            else:
                print("  Average        : N/A")
                print("  Minimum        : N/A")
                print("  Maximum        : N/A\n")
                
            print(f"Runtime          : {runtime:.1f} seconds\n")
            
    except Exception as exc:
        print(f"Error querying database for summary: {exc}")

    print("============================================================")
    print("SOC STREAM STOPPED")
    print("============================================================")


def run_wrapper():
    p = argparse.ArgumentParser(description="Real-Time Event Stream Wrapping Pipeline.")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--count", type=int, default=None)
    p.add_argument("--continuous", action="store_true", default=False)
    p.add_argument("--label", type=str, choices=["all", "benign", "attack"], default="all")
    p.add_argument("--source", type=str, default="realtime_dataset_replay")
    p.add_argument("--loop", action="store_true", default=False)
    
    args = p.parse_args()
    
    if args.count is None and not args.continuous:
        args.count = 20
        args.continuous = False

    consumer_count = args.count if not args.continuous else 9999999
    
    # Get current max event id to differentiate this session
    start_event_id = 0
    if DB_PATH.exists():
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute("SELECT MAX(id) FROM events")
                row = cur.fetchone()
                if row and row[0] is not None:
                    start_event_id = row[0]
        except Exception:
            pass

    start_time = time.time()
    
    print("\nStarting Background SOC Consumer Thread...")
    consumer_thread = threading.Thread(
        target=consume_events, 
        kwargs={'count': consumer_count, 'silent': False},
        daemon=True
    )
    consumer_thread.start()
    
    time.sleep(1.0) # Let the consumer bind completely
    
    try:
        run_realtime_producer(
            interval=args.interval,
            count=args.count,
            continuous=args.continuous,
            label_filter=args.label,
            source=args.source,
            loop=args.loop
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"\n[FATAL] Producer Error: {exc}")
        sys.exit(1)
        
    print("\nStopping Background Consumer (waiting up to 5s for drain)...")
    # Wait for consumer to process whatever is in the queue
    consumer_thread.join(timeout=5)
    
    # Print the requested summary
    print_demonstration_summary(start_event_id, start_time)


if __name__ == "__main__":
    try:
        run_wrapper()
    except KeyboardInterrupt:
        sys.exit(0)
