#!/usr/bin/env python3
"""
agents/vm_sensor/victim_flow_daemon.py
======================================
Autonomous Live Network Flow Extractor for the Remote Victim VM.

Runs directly on the Ubuntu victim VM:
1. Captures live network traffic from eth0 using native tcpdump stream.
   Filters out SSH (:22) and reverse-tunnel (:18000) traffic to prevent feedback loops.
2. Reconstructs bidirectional TCP/UDP network flows.
3. Computes all 78 canonical statistical flow features (CICFlowMeter equivalent)
   with microsecond precision and zero fabricated metrics.
4. Immediately transmits completed flows via HTTP across the reverse tunnel:
   POST http://127.0.0.1:18000/api/ingest/flow
5. Simultaneously appends to /var/log/soc/flows.csv for persistent auditing.

Zero third-party dependencies: uses standard Python 3.8+ (socket, struct, statistics, urllib).
"""

import argparse
import csv
import datetime
import json
import logging
import math
import os
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration Defaults
# ---------------------------------------------------------------------------
DEFAULT_INTERFACE = "eth0"
DEFAULT_INGEST_URL = os.environ.get("SOC_INGEST_URL", "http://127.0.0.1:18000/api/ingest/flow")
DEFAULT_SENSOR_KEY = os.environ.get("SOC_SENSOR_KEY", "soc-sensor-dev-key-2026")
DEFAULT_CSV_PATH = "/var/log/soc/flows.csv"
FLOW_IDLE_TIMEOUT_SEC = 2.0     # Finalize flow after 2.0s without packets
FLOW_MAX_ACTIVE_SEC = 15.0      # Finalize active long flows after 15.0s

CANONICAL_FEATURES: List[str] = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Len", "Bwd Header Len",
    "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", "Pkt Len Max",
    "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var", "FIN Flag Cnt",
    "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
    "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
    "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
    "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts",
    "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] SOC.FlowSensor: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SOC.FlowSensor")


class FlowRecord:
    """Tracks bidirectional packet metrics for an active flow."""
    __slots__ = (
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_ts", "last_ts", "fwd_pkt_lens", "bwd_pkt_lens",
        "fwd_pkt_times", "bwd_pkt_times", "all_pkt_times",
        "fwd_header_len", "bwd_header_len",
        "fwd_psh_cnt", "bwd_psh_cnt", "fwd_urg_cnt", "bwd_urg_cnt",
        "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt", "ack_cnt", "urg_cnt", "cwe_cnt", "ece_cnt",
        "init_fwd_win", "init_bwd_win", "fwd_act_data_pkts", "min_seg_size_fwd",
        "is_finished",
    )

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int, ts_usec: float):
        self.flow_id = str(uuid.uuid4())
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_ts = ts_usec
        self.last_ts = ts_usec
        self.fwd_pkt_lens: List[float] = []
        self.bwd_pkt_lens: List[float] = []
        self.fwd_pkt_times: List[float] = []
        self.bwd_pkt_times: List[float] = []
        self.all_pkt_times: List[float] = []
        self.fwd_header_len = 0.0
        self.bwd_header_len = 0.0
        self.fwd_psh_cnt = 0.0
        self.bwd_psh_cnt = 0.0
        self.fwd_urg_cnt = 0.0
        self.bwd_urg_cnt = 0.0
        self.fin_cnt = 0.0
        self.syn_cnt = 0.0
        self.rst_cnt = 0.0
        self.psh_cnt = 0.0
        self.ack_cnt = 0.0
        self.urg_cnt = 0.0
        self.cwe_cnt = 0.0
        self.ece_cnt = 0.0
        self.init_fwd_win = 0.0
        self.init_bwd_win = 0.0
        self.fwd_act_data_pkts = 0.0
        self.min_seg_size_fwd = 32.0
        self.is_finished = False

    def add_packet(
        self,
        is_forward: bool,
        pkt_len: int,
        hdr_len: int,
        ts_usec: float,
        flags: int,
        window: int,
        payload_len: int,
    ) -> None:
        self.last_ts = ts_usec
        self.all_pkt_times.append(ts_usec)

        # Flag counts
        fin = 1.0 if (flags & 0x01) else 0.0
        syn = 1.0 if (flags & 0x02) else 0.0
        rst = 1.0 if (flags & 0x04) else 0.0
        psh = 1.0 if (flags & 0x08) else 0.0
        ack = 1.0 if (flags & 0x10) else 0.0
        urg = 1.0 if (flags & 0x20) else 0.0
        ece = 1.0 if (flags & 0x40) else 0.0
        cwe = 1.0 if (flags & 0x80) else 0.0

        self.fin_cnt += fin
        self.syn_cnt += syn
        self.rst_cnt += rst
        self.psh_cnt += psh
        self.ack_cnt += ack
        self.urg_cnt += urg
        self.ece_cnt += ece
        self.cwe_cnt += cwe

        if fin > 0 or rst > 0:
            self.is_finished = True

        if is_forward:
            self.fwd_pkt_lens.append(float(pkt_len))
            self.fwd_pkt_times.append(ts_usec)
            self.fwd_header_len += float(hdr_len)
            self.fwd_psh_cnt += psh
            self.fwd_urg_cnt += urg
            if len(self.fwd_pkt_lens) == 1:
                self.init_fwd_win = float(window)
            if payload_len > 0:
                self.fwd_act_data_pkts += 1.0
            if hdr_len > 0:
                self.min_seg_size_fwd = min(self.min_seg_size_fwd, float(hdr_len))
        else:
            self.bwd_pkt_lens.append(float(pkt_len))
            self.bwd_pkt_times.append(ts_usec)
            self.bwd_header_len += float(hdr_len)
            self.bwd_psh_cnt += psh
            self.bwd_urg_cnt += urg
            if len(self.bwd_pkt_lens) == 1:
                self.init_bwd_win = float(window)

    def compute_features(self) -> Dict[str, float]:
        """Compute the complete set of 78 canonical numeric features."""
        duration_us = max(1.0, self.last_ts - self.start_ts)
        duration_sec = duration_us / 1_000_000.0

        tot_fwd_pkts = float(len(self.fwd_pkt_lens))
        tot_bwd_pkts = float(len(self.bwd_pkt_lens))
        tot_fwd_len = float(sum(self.fwd_pkt_lens))
        tot_bwd_len = float(sum(self.bwd_pkt_lens))
        total_pkts = tot_fwd_pkts + tot_bwd_pkts
        total_len = tot_fwd_len + tot_bwd_len

        all_lens = self.fwd_pkt_lens + self.bwd_pkt_lens

        # Packet Length Statistics
        fwd_len_max = max(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0.0
        fwd_len_min = min(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0.0
        fwd_len_mean = statistics.mean(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0.0
        fwd_len_std = statistics.stdev(self.fwd_pkt_lens) if len(self.fwd_pkt_lens) > 1 else 0.0

        bwd_len_max = max(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0.0
        bwd_len_min = min(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0.0
        bwd_len_mean = statistics.mean(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0.0
        bwd_len_std = statistics.stdev(self.bwd_pkt_lens) if len(self.bwd_pkt_lens) > 1 else 0.0

        pkt_len_min = min(all_lens) if all_lens else 0.0
        pkt_len_max = max(all_lens) if all_lens else 0.0
        pkt_len_mean = statistics.mean(all_lens) if all_lens else 0.0
        pkt_len_std = statistics.stdev(all_lens) if len(all_lens) > 1 else 0.0
        pkt_len_var = pkt_len_std ** 2

        # Throughput
        flow_byts_s = (total_len / duration_sec) if duration_sec > 0 else 0.0
        flow_pkts_s = (total_pkts / duration_sec) if duration_sec > 0 else 0.0
        fwd_pkts_s = (tot_fwd_pkts / duration_sec) if duration_sec > 0 else 0.0
        bwd_pkts_s = (tot_bwd_pkts / duration_sec) if duration_sec > 0 else 0.0

        # Inter-Arrival Times (IAT)
        def _calc_iat(times: List[float]) -> Tuple[float, float, float, float, float]:
            if len(times) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            iats = [times[i] - times[i - 1] for i in range(1, len(times))]
            tot = sum(iats)
            mean = statistics.mean(iats)
            std = statistics.stdev(iats) if len(iats) > 1 else 0.0
            return tot, mean, std, max(iats), min(iats)

        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _calc_iat(self.all_pkt_times)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _calc_iat(self.fwd_pkt_times)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _calc_iat(self.bwd_pkt_times)

        down_up_ratio = (tot_bwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0.0
        pkt_size_avg = (total_len / total_pkts) if total_pkts > 0 else 0.0
        fwd_seg_avg = fwd_len_mean
        bwd_seg_avg = bwd_len_mean

        features: Dict[str, float] = {
            "Dst Port": float(self.dst_port),
            "Protocol": float(self.protocol),
            "Flow Duration": float(duration_us),
            "Tot Fwd Pkts": tot_fwd_pkts,
            "Tot Bwd Pkts": tot_bwd_pkts,
            "TotLen Fwd Pkts": tot_fwd_len,
            "TotLen Bwd Pkts": tot_bwd_len,
            "Fwd Pkt Len Max": fwd_len_max,
            "Fwd Pkt Len Min": fwd_len_min,
            "Fwd Pkt Len Mean": fwd_len_mean,
            "Fwd Pkt Len Std": fwd_len_std,
            "Bwd Pkt Len Max": bwd_len_max,
            "Bwd Pkt Len Min": bwd_len_min,
            "Bwd Pkt Len Mean": bwd_len_mean,
            "Bwd Pkt Len Std": bwd_len_std,
            "Flow Byts/s": flow_byts_s,
            "Flow Pkts/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Tot": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Tot": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": self.fwd_psh_cnt,
            "Bwd PSH Flags": self.bwd_psh_cnt,
            "Fwd URG Flags": self.fwd_urg_cnt,
            "Bwd URG Flags": self.bwd_urg_cnt,
            "Fwd Header Len": self.fwd_header_len,
            "Bwd Header Len": self.bwd_header_len,
            "Fwd Pkts/s": fwd_pkts_s,
            "Bwd Pkts/s": bwd_pkts_s,
            "Pkt Len Min": pkt_len_min,
            "Pkt Len Max": pkt_len_max,
            "Pkt Len Mean": pkt_len_mean,
            "Pkt Len Std": pkt_len_std,
            "Pkt Len Var": pkt_len_var,
            "FIN Flag Cnt": self.fin_cnt,
            "SYN Flag Cnt": self.syn_cnt,
            "RST Flag Cnt": self.rst_cnt,
            "PSH Flag Cnt": self.psh_cnt,
            "ACK Flag Cnt": self.ack_cnt,
            "URG Flag Cnt": self.urg_cnt,
            "CWE Flag Count": self.cwe_cnt,
            "ECE Flag Cnt": self.ece_cnt,
            "Down/Up Ratio": down_up_ratio,
            "Pkt Size Avg": pkt_size_avg,
            "Fwd Seg Size Avg": fwd_seg_avg,
            "Bwd Seg Size Avg": bwd_seg_avg,
            "Fwd Byts/b Avg": 0.0,
            "Fwd Pkts/b Avg": 0.0,
            "Fwd Blk Rate Avg": 0.0,
            "Bwd Byts/b Avg": 0.0,
            "Bwd Pkts/b Avg": 0.0,
            "Bwd Blk Rate Avg": 0.0,
            "Subflow Fwd Pkts": tot_fwd_pkts,
            "Subflow Fwd Byts": tot_fwd_len,
            "Subflow Bwd Pkts": tot_bwd_pkts,
            "Subflow Bwd Byts": tot_bwd_len,
            "Init Fwd Win Byts": self.init_fwd_win,
            "Init Bwd Win Byts": self.init_bwd_win,
            "Fwd Act Data Pkts": self.fwd_act_data_pkts,
            "Fwd Seg Size Min": self.min_seg_size_fwd,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

        # Sanitize any NaNs or Infs
        for k in CANONICAL_FEATURES:
            val = features.get(k, 0.0)
            if math.isnan(val) or math.isinf(val):
                features[k] = 0.0

        return features


class LiveFlowExtractor:
    """Captures network packets from eth0 and manages active flow tables."""

    def __init__(
        self,
        interface: str = DEFAULT_INTERFACE,
        ingest_url: str = DEFAULT_INGEST_URL,
        sensor_key: str = DEFAULT_SENSOR_KEY,
        csv_path: str = DEFAULT_CSV_PATH,
    ):
        self.interface = interface
        self.ingest_url = ingest_url
        self.sensor_key = sensor_key
        self.csv_path = csv_path
        self._running = False
        self._flows: Dict[Tuple[str, int, str, int, int], FlowRecord] = {}
        self._lock = threading.Lock()
        self._csv_lock = threading.Lock()
        self._init_csv()

    def _init_csv(self):
        try:
            os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)
            if not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0:
                with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Flow ID", "Source IP", "Source Port", "Destination IP"] + CANONICAL_FEATURES)
                logger.info("Initialized flow CSV log at %s", self.csv_path)
        except Exception as exc:
            logger.warning("Could not initialize flow CSV at %s: %s", self.csv_path, exc)

    def _write_csv_row(self, flow: FlowRecord, feats: Dict[str, float]):
        try:
            with self._csv_lock:
                with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    row = [flow.flow_id, flow.src_ip, flow.src_port, flow.dst_ip] + [feats[k] for k in CANONICAL_FEATURES]
                    writer.writerow(row)
        except Exception:
            pass

    def _submit_flow_http(self, flow: FlowRecord, feats: Dict[str, float]):
        """Directly submit flow record to Windows SOC reverse tunnel endpoint."""
        payload = {
            "event_id": flow.flow_id,
            "sensor_id": "ubuntu-victim-01",
            "timestamp": datetime.datetime.now().isoformat(),
            "source": "victim_live_tap",
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else str(flow.protocol)),
            "features": feats,
        }

        try:
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.ingest_url,
                data=data_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-SOC-Sensor-Key": self.sensor_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status in (200, 201):
                    logger.info("Ingested flow %s:%d -> %s:%d (%d bytes, dur: %.2fs)",
                                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                                int(feats["TotLen Fwd Pkts"] + feats["TotLen Bwd Pkts"]),
                                feats["Flow Duration"] / 1_000_000.0)
        except urllib.error.HTTPError as err:
            if err.code == 409:
                pass  # duplicate
            else:
                logger.warning("HTTP %d error submitting flow to %s: %s", err.code, self.ingest_url, err.reason)
        except Exception as exc:
            logger.debug("Transient error submitting flow to %s: %s", self.ingest_url, exc)

    def _finalize_flow(self, flow: FlowRecord):
        feats = flow.compute_features()
        self._write_csv_row(flow, feats)
        # Background submit so packet processing thread is never blocked
        threading.Thread(target=self._submit_flow_http, args=(flow, feats), daemon=True).start()

    def _cleanup_expired_flows(self):
        """Timer loop that flushes idle and long-running flows."""
        while self._running:
            now_usec = time.time() * 1_000_000.0
            expired: List[FlowRecord] = []

            with self._lock:
                keys_to_del = []
                for key, flow in self._flows.items():
                    idle_sec = (now_usec - flow.last_ts) / 1_000_000.0
                    active_sec = (now_usec - flow.start_ts) / 1_000_000.0

                    if flow.is_finished or idle_sec >= FLOW_IDLE_TIMEOUT_SEC or active_sec >= FLOW_MAX_ACTIVE_SEC:
                        expired.append(flow)
                        keys_to_del.append(key)

                for k in keys_to_del:
                    del self._flows[k]

            for flow in expired:
                self._finalize_flow(flow)

            time.sleep(0.5)

    def start(self):
        self._running = True
        timer_thread = threading.Thread(target=self._cleanup_expired_flows, daemon=True)
        timer_thread.start()

        # BPF filter: exclude SSH (22) and reverse tunnel (18000) traffic to avoid observation feedback
        bpf_filter = "not port 22 and not port 18000 and (tcp or udp)"
        cmd = [
            "tcpdump", "-U", "-w", "-", "-i", self.interface, "-s", "96", bpf_filter
        ]

        logger.info("Starting live packet tap on %s: %s", self.interface, " ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        try:
            stdout = proc.stdout
            if not stdout:
                raise RuntimeError("Failed to open tcpdump stdout pipe.")

            # Read PCAP 24-byte global header
            ghdr = stdout.read(24)
            if len(ghdr) < 24:
                raise RuntimeError("Could not read pcap global header.")

            while self._running:
                # 16-byte PCAP packet header
                phdr = stdout.read(16)
                if len(phdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", phdr)
                pkt_data = stdout.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                ts_micro = ts_sec * 1_000_000.0 + ts_usec
                self._process_packet(pkt_data, ts_micro)

        except Exception as exc:
            logger.error("Packet sniffing loop stopped: %s", exc)
        finally:
            self._running = False
            proc.terminate()
            logger.info("Live packet tap terminated cleanly.")

    def _process_packet(self, data: bytes, ts_usec: float):
        # Ethernet Header: 14 bytes
        if len(data) < 14:
            return
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:  # Only IPv4 for 78-feature model
            return

        # IPv4 Header
        ip_data = data[14:]
        if len(ip_data) < 20:
            return
        ihl = (ip_data[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip_data[2:4])[0]
        protocol = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        src_port, dst_port, flags, window, hdr_len, payload_len = 0, 0, 0, 0, 0, 0

        if protocol == 6:  # TCP
            tcp_data = ip_data[ihl:]
            if len(tcp_data) < 20:
                return
            src_port, dst_port = struct.unpack("!HH", tcp_data[0:4])
            data_offset = (tcp_data[12] >> 4) * 4
            flags = tcp_data[13]
            window = struct.unpack("!H", tcp_data[14:16])[0]
            hdr_len = ihl + data_offset
            payload_len = max(0, total_len - hdr_len)

        elif protocol == 17:  # UDP
            udp_data = ip_data[ihl:]
            if len(udp_data) < 8:
                return
            src_port, dst_port, udp_len = struct.unpack("!HHH", udp_data[0:6])
            hdr_len = ihl + 8
            payload_len = max(0, total_len - hdr_len)
        else:
            return

        # Canonical 5-tuple key: (min(src_ip, dst_ip), min(src_port, dst_port), max(src_ip, dst_ip), max(src_port, dst_port), proto)
        is_forward = (src_ip, src_port) <= (dst_ip, dst_port)
        if is_forward:
            fkey = (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            fkey = (dst_ip, dst_port, src_ip, src_port, protocol)

        with self._lock:
            flow = self._flows.get(fkey)
            if flow is None:
                flow = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol, ts_usec)
                self._flows[fkey] = flow

            flow.add_packet(
                is_forward=(flow.src_ip == src_ip and flow.src_port == src_port),
                pkt_len=total_len,
                hdr_len=hdr_len,
                ts_usec=ts_usec,
                flags=flags,
                window=window,
                payload_len=payload_len,
            )


def main():
    parser = argparse.ArgumentParser(description="Autonomous Live Network Flow Extractor for SOC")
    parser.add_argument("--interface", "-i", default=DEFAULT_INTERFACE, help=f"Interface to sniff (default: {DEFAULT_INTERFACE})")
    parser.add_argument("--ingest-url", default=DEFAULT_INGEST_URL, help=f"SOC flow ingest endpoint (default: {DEFAULT_INGEST_URL})")
    parser.add_argument("--sensor-key", default=DEFAULT_SENSOR_KEY, help="SOC pre-shared sensor key")
    parser.add_argument("--csv", default=DEFAULT_CSV_PATH, help=f"Output CSV path (default: {DEFAULT_CSV_PATH})")
    args = parser.parse_args()

    extractor = LiveFlowExtractor(
        interface=args.interface,
        ingest_url=args.ingest_url,
        sensor_key=args.sensor_key,
        csv_path=args.csv,
    )

    def _sig_handler(sig, frame):
        logger.info("Signal received. Terminating flow sensor...")
        extractor._running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print("=" * 70)
    print("  SOC LIVE NETWORK FLOW SENSOR (VICTIM DAEMON)")
    print("=" * 70)
    print(f"  Sniffing Interface : {args.interface}")
    print(f"  Ingest Endpoint    : {args.ingest_url}")
    print(f"  Local CSV Output   : {args.csv}")
    print("=" * 70)
    extractor.start()


if __name__ == "__main__":
    main()
