"""
realtime_monitor.py
===================
Real-Time SOC Prediction Monitor (Observation Layer).
Continuously polls the SQLite database for newly generated alerts,
displaying predictions dynamically in the terminal.

Multi-Agent SOC Project -- Stage 8A (Modification)
"""

import argparse
import sys
import time
import sqlite3
import pathlib
import os

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from storage.config import DB_PATH
except ImportError:
    DB_PATH = PROJECT_ROOT / "data" / "soc.db"


class LiveStats:
    def __init__(self):
        self.events_processed = 0
        self.benign = 0
        self.attacks = 0
        self.normal = 0
        self.anomalous = 0
        self.alerts = 0
        self.incidents = 0
        self.latencies = []

    def process_event(self, nd_pred, ad_pred, num_alerts, has_incident, latency):
        self.events_processed += 1
        
        if nd_pred and nd_pred.lower() == "benign":
            self.benign += 1
        elif nd_pred and nd_pred.lower() != "benign":
            self.attacks += 1
            
        if ad_pred and ad_pred.lower() == "normal":
            self.normal += 1
        elif ad_pred and ad_pred.lower() == "anomalous":
            self.anomalous += 1
            
        self.alerts += num_alerts
        if has_incident:
            self.incidents += 1
            
        if latency is not None:
            self.latencies.append(latency)

    def print_summary(self):
        avg_lat, min_lat, max_lat = 0.0, 0.0, 0.0
        if self.latencies:
            avg_lat = sum(self.latencies) / len(self.latencies)
            min_lat = min(self.latencies)
            max_lat = max(self.latencies)

        print("=" * 60)
        print("LIVE SOC STATISTICS")
        print("=" * 60)
        print()
        print(f"Events Processed : {self.events_processed}")
        print(f"Benign           : {self.benign}")
        print(f"Attacks          : {self.attacks}")
        print(f"Anomalous        : {self.anomalous}")
        print(f"Alerts           : {self.alerts}")
        print(f"Incidents        : {self.incidents}")
        print()
        if self.latencies:
            print(f"Average Latency  : {avg_lat*1000:.1f} ms")
            print(f"Min Latency      : {min_lat*1000:.0f} ms")
            print(f"Max Latency      : {max_lat*1000:.0f} ms")
        else:
            print("Average Latency  : N/A")
            print("Min Latency      : N/A")
            print("Max Latency      : N/A")
        print()
        print("=" * 60)


def parse_args():
    p = argparse.ArgumentParser(description="Real-Time SOC Prediction Monitor")
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--show-existing", action="store_true", default=False)
    p.add_argument("--once", action="store_true", default=False)
    p.add_argument("--db", type=str, default=str(DB_PATH))
    args = p.parse_args()
    if args.interval < 0:
        print("[FATAL] Interval cannot be negative.")
        sys.exit(1)
    args.db_path = pathlib.Path(args.db)
    return args


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_event_data(conn, event_id):
    # Get all alerts for this event
    cur = conn.execute("SELECT * FROM alerts WHERE event_id = ? ORDER BY id ASC", (event_id,))
    alerts = cur.fetchall()
    
    nd_alert = next((a for a in alerts if a['agent'] == 'Network Detection Agent'), None)
    ad_alert = next((a for a in alerts if a['agent'] == 'Anomaly Detection Agent'), None)
    
    # Process alerts generated
    alerts_generated = []
    for a in alerts:
        # A real alert would usually have severity HIGH or MEDIUM, 
        # but to keep counting simple, we count actual threat alerts/anomalies
        # However, the instructions say: "If no alert was generated: Status: No alert generated"
        # We will consider an 'alert' as generated if the severity is not LOW/NONE.
        # Let's just output the primary one from Network or Anomaly if severity > LOW.
        if a['severity'] and a['severity'].upper() not in ["LOW", "NONE"]:
            alerts_generated.append(a)

    cur = conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,))
    incidents = cur.fetchall()
    incident = incidents[0] if incidents else None

    # We assume timestamp and processing time from the network detection alert
    timestamp = nd_alert['timestamp'] if nd_alert else "N/A"
    proc_time = nd_alert['processing_time_s'] if nd_alert else None
    
    cur = conn.execute("SELECT source FROM events WHERE event_id = ?", (event_id,))
    ev_row = cur.fetchone()
    source = ev_row['source'] if ev_row else "unknown"

    return nd_alert, ad_alert, alerts_generated, incident, timestamp, proc_time, source


def format_output(event_id, nd_alert, ad_alert, alerts_generated, incident, timestamp, proc_time, source):
    lines = []
    lines.append(f"[{timestamp}] EVENT RECEIVED\n")
    lines.append(f"Event ID       : {event_id}")
    lines.append(f"Source         : {source}\n")
    
    # NETWORK DETECTION
    lines.append("NETWORK DETECTION")
    if nd_alert:
        pred = nd_alert['prediction'].upper() if nd_alert['prediction'] else "UNKNOWN"
        lines.append(f"Prediction     : {'ATTACK' if pred == 'INFILTERATION' else pred}")
        conf = nd_alert['confidence']
        lines.append(f"Confidence     : {conf*100:.2f}%" if conf is not None else "Confidence     : N/A")
    else:
        lines.append("Prediction     : N/A")
        
    lines.append("")
    
    # ANOMALY DETECTION
    lines.append("ANOMALY DETECTION")
    if ad_alert:
        lines.append(f"Prediction     : {ad_alert['prediction'].upper() if ad_alert['prediction'] else 'UNKNOWN'}")
        score = ad_alert['confidence'] # Score is stored in confidence column
        lines.append(f"Anomaly Score  : {score:.6f}" if score is not None else "Anomaly Score  : N/A")
    else:
        lines.append("Prediction     : N/A")
        
    lines.append("")
    
    # FINAL STATUS
    lines.append("FINAL STATUS")
    if incident:
        # If there's an incident, we take its status
        lines.append(f"Status         : {incident['prediction'].upper()}")
        lines.append(f"Severity       : {incident['severity'].upper()}")
    else:
        # Base it on the alerts if there's no overall incident
        nd_pred = nd_alert['prediction'].upper() if nd_alert and nd_alert['prediction'] else "BENIGN"
        ad_pred = ad_alert['prediction'].upper() if ad_alert and ad_alert['prediction'] else "NORMAL"
        if nd_pred == "INFILTERATION" or ad_pred == "ANOMALOUS":
            lines.append("Status         : THREAT")
            highest_sev = "LOW"
            if alerts_generated:
                highest_sev = alerts_generated[-1]['severity'].upper()
            lines.append(f"Severity       : {highest_sev}")
        else:
            lines.append("Status         : BENIGN")
            lines.append("Severity       : NONE")
            
    lines.append("")
    
    # ALERT
    lines.append("ALERT")
    if alerts_generated:
        primary = alerts_generated[0]
        p_pred = primary['prediction'] if primary['prediction'] != 'Infilteration' else 'ATTACK'
        lines.append(f"Prediction     : {p_pred}")
        lines.append(f"Severity       : {primary['severity'].upper()}")
        lines.append(f"Alert ID       : {primary['alert_id']}")
    else:
        lines.append("Status         : No alert generated")
    
    lines.append("")
    
    # INCIDENT
    lines.append("INCIDENT")
    if incident:
        lines.append(f"Incident ID    : {incident['incident_id']}")
        lines.append(f"Severity       : {incident['severity'].upper()}")
        lines.append(f"Status         : {incident['status']}")
    else:
        lines.append("Status         : No incident created")
        
    lines.append("")
    if proc_time is not None:
        lines.append(f"Processing Time: {int(proc_time*1000)} ms")
    else:
        lines.append("Processing Time: N/A")
        
    lines.append("-" * 60)
    return "\n".join(lines)


def run_monitor(args):
    if not args.db_path.exists():
        print(f"[FATAL] Database not found at: {args.db_path}")
        sys.exit(1)

    print("╔════════════════════════════════════════════════════════════╗")
    print("║              REAL-TIME AI SECURITY OPERATIONS CENTER       ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

    stats = LiveStats()

    last_id = 0
    try:
        with sqlite3.connect(args.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            try:
                conn.execute("SELECT 1 FROM events LIMIT 1")
            except sqlite3.OperationalError as exc:
                print(f"[FATAL] Could not read events table. Error: {exc}")
                sys.exit(1)

            if not args.show_existing:
                cur = conn.execute("SELECT MAX(id) FROM events")
                row = cur.fetchone()
                if row and row[0] is not None:
                    last_id = row[0]

            while True:
                # Poll new events
                cur = conn.execute("SELECT id, event_id FROM events WHERE id > ? ORDER BY id ASC", (last_id,))
                rows = cur.fetchall()
                
                for r in rows:
                    event_id = r['event_id']
                    
                    # It's possible the event was just inserted but alerts aren't there yet.
                    # We will briefly loop/wait up to 0.5s for the ND alert to appear.
                    waits = 0
                    while waits < 5:
                        nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, event_id)
                        if nd_a is not None:
                            break
                        time.sleep(0.1)
                        waits += 1

                    if nd_a is None:
                        # Skip if still no alert, or just process with what we have
                        pass
                    
                    output = format_output(event_id, nd_a, ad_a, alerts_gen, inc, ts, pt, src)
                    print(output)
                    
                    nd_pred = nd_a['prediction'] if nd_a else "BENIGN"
                    ad_pred = ad_a['prediction'] if ad_a else "NORMAL"
                    stats.process_event(nd_pred, ad_pred, len(alerts_gen), inc is not None, pt)
                    
                    last_id = max(last_id, r['id'])
                
                if rows and not args.once:
                    stats.print_summary()
                
                if args.once:
                    break
                    
                time.sleep(args.interval)
                
    except KeyboardInterrupt:
        print("\n[Monitor] Stopped gracefully by user (Ctrl+C).")
        stats.print_summary()
        sys.exit(0)
    except Exception as exc:
        print(f"\n[FATAL] Database connection or polling failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    run_monitor(args)

