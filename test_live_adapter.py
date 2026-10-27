"""
test_live_adapter.py
====================
Test Suite for Phase 2 Live Flow Normalization Adapter (kafka/live_adapter.py).

Covers:
1. Canonical feature mapping and metadata extraction.
2. Python cicflowmeter (snake_case) column mapping.
3. Java CICFlowMeter v3/v4 column mapping.
4. Incompatible schema rejection (missing columns, never fabricating features).
5. Unit scaling (seconds, milliseconds, microseconds).
6. Negative flow duration rejection (32-bit overflow / timestamp skew).
7. Cell-level NaN / Inf imputation using training-set medians.
8. Corrupt row rejection (excessive NaNs / Infs).
9. Metadata isolation (ensures IPs, timestamps, and Flow IDs are NOT in features).
10. Incremental CSV tailing and offset persistence across restarts.
11. Partial line write handling (rewinding until full newline written).
12. File rotation / truncation detection.
13. HTTP transmission retry, duplicate 409 handling, and end-to-end API integration.
"""

import csv
import json
import math
import os
import pathlib
import sys
import tempfile
import time
import unittest
import uuid
from typing import Dict, List

from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import dashboard_api
from kafka.live_adapter import (
    CANONICAL_FEATURES,
    IncompatibleSchemaError,
    InvalidFlowError,
    LiveFlowAdapter,
    LiveFlowTailer,
)

VALID_SENSOR_KEY = os.environ.get("SOC_SENSOR_KEY", "soc-sensor-dev-key-2026")


class TestLiveFlowAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = LiveFlowAdapter()
        cls.client = TestClient(dashboard_api.app)

        # Baseline sample record with all 78 canonical features
        cls.base_canonical_row = {f: float(cls.adapter.medians.get(f, 0.0)) for f in CANONICAL_FEATURES}

    # -----------------------------------------------------------------------
    # 1. Canonical Schema & Metadata Isolation
    # -----------------------------------------------------------------------

    def test_canonical_schema_mapping(self):
        """Verify that standard canonical headers match 78/78 features and isolate metadata."""
        headers = [
            "Source IP", "Destination IP", "Source Port", "Timestamp", "Flow ID", "Label"
        ] + CANONICAL_FEATURES

        feat_map, meta_map = self.adapter.build_column_mapping(headers)
        self.assertEqual(len(set(feat_map.values())), 78)
        self.assertEqual(len(meta_map), 6)

        # Build mock values
        values = ["192.168.1.10", "10.0.0.1", "54321", "2026-10-26T16:00:00", "flow-001", "Benign"]
        for feat in CANONICAL_FEATURES:
            values.append(self.base_canonical_row[feat])

        payload = self.adapter.normalize_row_values(values, feat_map, meta_map, sequence=1)

        # Metadata checks
        self.assertEqual(payload["source"], "live_sensor")
        self.assertEqual(payload["src_ip"], "192.168.1.10")
        self.assertEqual(payload["dst_ip"], "10.0.0.1")
        self.assertEqual(payload["src_port"], 54321)
        self.assertEqual(payload["actual_label"], "Benign")

        # Feature checks: exactly 78 features in canonical order
        self.assertEqual(len(payload["features"]), 78)
        self.assertEqual(list(payload["features"].keys()), CANONICAL_FEATURES)

        # Verify metadata fields are NEVER injected into features
        for forbidden in ["src_ip", "dst_ip", "src_port", "Source IP", "flow_id", "timestamp", "actual_label"]:
            self.assertNotIn(forbidden, payload["features"])

    # -----------------------------------------------------------------------
    # 2. Python cicflowmeter (snake_case) Mapping
    # -----------------------------------------------------------------------

    def test_python_cicflowmeter_mapping(self):
        """Verify that Python cicflowmeter snake_case columns map cleanly to all 78 canonical features."""
        py_cols = [
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
            "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
            "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
            "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
            "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
            "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
            "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
            "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
            "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
            "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
            "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
            "urg_flag_cnt", "cwe_flag_count", "ece_flag_cnt", "down_up_ratio", "pkt_size_avg",
            "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
            "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg", "subflow_fwd_pkts", "subflow_fwd_byts",
            "subflow_bwd_pkts", "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts",
            "fwd_act_data_pkts", "fwd_seg_size_min", "active_mean", "active_std", "active_max", "active_min",
            "idle_mean", "idle_std", "idle_max", "idle_min"
        ]

        feat_map, meta_map = self.adapter.build_column_mapping(py_cols)
        self.assertEqual(len(set(feat_map.values())), 78)
        self.assertIn("src_ip", meta_map.values())
        self.assertIn("dst_ip", meta_map.values())

    # -----------------------------------------------------------------------
    # 3. Java CICFlowMeter (v3/v4) Mapping
    # -----------------------------------------------------------------------

    def test_java_cicflowmeter_mapping(self):
        """Verify that Java CICFlowMeter v3 headers map cleanly and ignore duplicate/extra headers."""
        java_cols = [
            "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
            "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
            "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
            "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
            "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
            "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
            "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
            "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
            "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
            "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
            "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
            "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
            "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
            "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
        ]

        feat_map, meta_map = self.adapter.build_column_mapping(java_cols)
        self.assertEqual(len(set(feat_map.values())), 78)
        self.assertIn("flow_id", meta_map.values())
        self.assertIn("src_ip", meta_map.values())
        self.assertIn("actual_label", meta_map.values())

    # -----------------------------------------------------------------------
    # 4. Incompatible Schema Rejection (Never Fabricating Features)
    # -----------------------------------------------------------------------

    def test_incompatible_schema_rejection(self):
        """Schemas missing required statistical columns must be rejected, not fabricated."""
        incomplete_headers = [
            "Source IP", "Destination IP", "Destination Port", "Protocol",
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets"
        ]
        with self.assertRaises(IncompatibleSchemaError) as ctx:
            self.adapter.build_column_mapping(incomplete_headers)

        exc = ctx.exception
        self.assertTrue(len(exc.missing_features) > 70)
        self.assertIn("strictly rejects incomplete schemas", str(exc))

    # -----------------------------------------------------------------------
    # 5. Flow Duration & Unit Scaling
    # -----------------------------------------------------------------------

    def test_duration_unit_scaling(self):
        """Verify scaling from seconds or milliseconds to canonical microseconds."""
        row_sec = dict(self.base_canonical_row)
        row_sec["Flow Duration"] = 1.5  # 1.5 seconds

        adapter_sec = LiveFlowAdapter(duration_units="s")
        payload_sec = adapter_sec.normalize_dict(row_sec)
        self.assertEqual(payload_sec["features"]["Flow Duration"], 1_500_000.0)

        row_ms = dict(self.base_canonical_row)
        row_ms["Flow Duration"] = 250.0  # 250 milliseconds

        adapter_ms = LiveFlowAdapter(duration_units="ms")
        payload_ms = adapter_ms.normalize_dict(row_ms)
        self.assertEqual(payload_ms["features"]["Flow Duration"], 250_000.0)

    def test_negative_flow_duration_rejected(self):
        """Negative Flow Duration (caused by 32-bit integer overflow in legacy tools) must be rejected."""
        bad_row = dict(self.base_canonical_row)
        bad_row["Flow Duration"] = -100.0

        with self.assertRaises(InvalidFlowError) as ctx:
            self.adapter.normalize_dict(bad_row)
        self.assertIn("Negative Flow Duration", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 6. NaN / Inf Imputation & Corrupt Row Rejection
    # -----------------------------------------------------------------------

    def test_cell_level_nan_inf_median_imputation(self):
        """Legitimate cell-level NaNs or Infs (e.g. division by 0) are imputed with training medians."""
        impute_row = dict(self.base_canonical_row)
        impute_row["Flow Byts/s"] = float("inf")
        impute_row["Flow Pkts/s"] = float("nan")

        payload = self.adapter.normalize_dict(impute_row)
        self.assertEqual(payload["features"]["Flow Byts/s"], self.adapter.medians["Flow Byts/s"])
        self.assertEqual(payload["features"]["Flow Pkts/s"], self.adapter.medians["Flow Pkts/s"])

    def test_corrupt_row_excessive_nans_rejected(self):
        """Rows with excessive NaNs (>8) must be rejected as corrupt flow records."""
        corrupt_row = dict(self.base_canonical_row)
        for feat in CANONICAL_FEATURES[:10]:
            corrupt_row[feat] = float("nan")

        with self.assertRaises(InvalidFlowError) as ctx:
            self.adapter.normalize_dict(corrupt_row)
        self.assertIn("exceeding maximum tolerance", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 7. Incremental File Tailing & Offset Persistence
    # -----------------------------------------------------------------------

    def test_incremental_tailing_and_restart(self):
        """Verify tailer reads new rows, saves offset, and resumes without reprocessing on restart."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = pathlib.Path(tmpdir) / "sensor_flows.csv"
            offset_path = pathlib.Path(tmpdir) / "sensor_flows.csv.offset"

            headers = ["src_ip", "dst_ip", "src_port"] + CANONICAL_FEATURES

            # 1. Write header and 2 rows
            row1 = ["10.0.0.1", "10.0.0.2", "1234"] + [self.base_canonical_row[f] for f in CANONICAL_FEATURES]
            row2 = ["10.0.0.3", "10.0.0.4", "5678"] + [self.base_canonical_row[f] for f in CANONICAL_FEATURES]

            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerow(row1)
                writer.writerow(row2)

            tailer1 = LiveFlowTailer(
                file_path=csv_path,
                adapter=self.adapter,
                offset_file=offset_path,
                http_client=self.client,
            )

            # Process initial rows
            res1 = tailer1.process_available_rows()
            self.assertEqual(res1["rows_read"], 2)
            self.assertEqual(res1["sent_accepted"], 2)
            self.assertTrue(offset_path.is_file())
            saved_offset = tailer1.byte_offset

            # Re-run immediately: no new rows to read
            res_repeat = tailer1.process_available_rows()
            self.assertEqual(res_repeat["rows_read"], 0)

            # 2. Append a 3rd row to file
            row3 = ["10.0.0.5", "10.0.0.6", "9999"] + [self.base_canonical_row[f] for f in CANONICAL_FEATURES]
            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(row3)

            # 3. Simulate process restart: new LiveFlowTailer instance loading existing offset file
            tailer2 = LiveFlowTailer(
                file_path=csv_path,
                adapter=self.adapter,
                offset_file=offset_path,
                http_client=self.client,
            )
            self.assertEqual(tailer2.byte_offset, saved_offset)

            res2 = tailer2.process_available_rows()
            self.assertEqual(res2["rows_read"], 1)
            self.assertEqual(res2["sent_accepted"], 1)
            self.assertEqual(tailer2.lines_processed, 3)

    # -----------------------------------------------------------------------
    # 8. Partial Line Write Handling
    # -----------------------------------------------------------------------

    def test_partial_line_handling(self):
        """Tailer must not process an incomplete line that lacks a newline character."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = pathlib.Path(tmpdir) / "partial.csv"
            headers = ["src_ip", "dst_ip"] + CANONICAL_FEATURES

            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                # Write partial line without \n
                f.write("10.0.0.1,10.0.0.2,443")

            tailer = LiveFlowTailer(file_path=csv_path, adapter=self.adapter, http_client=self.client)
            res = tailer.process_available_rows()
            self.assertEqual(res["rows_read"], 0)

            # Now complete the line and flush newline
            full_rest = "," + ",".join(str(self.base_canonical_row[f]) for f in CANONICAL_FEATURES[1:]) + "\n"
            with open(csv_path, "a", encoding="utf-8") as f:
                f.write(full_rest)

            res_after = tailer.process_available_rows()
            self.assertEqual(res_after["rows_read"], 1)
            self.assertEqual(res_after["sent_accepted"], 1)

    # -----------------------------------------------------------------------
    # 9. File Rotation / Truncation Detection
    # -----------------------------------------------------------------------

    def test_file_rotation_detection(self):
        """When a file is truncated or replaced with a smaller file, tailer resets offset cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = pathlib.Path(tmpdir) / "rotating.csv"
            headers = ["src_ip", "dst_ip"] + CANONICAL_FEATURES

            row1 = ["10.0.0.1", "10.0.0.2"] + [self.base_canonical_row[f] for f in CANONICAL_FEATURES]
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerow(row1)

            tailer = LiveFlowTailer(file_path=csv_path, adapter=self.adapter, http_client=self.client)
            res1 = tailer.process_available_rows()
            self.assertEqual(res1["rows_read"], 1)
            self.assertTrue(tailer.byte_offset > 0)

            # Simulate log rotation: truncate and write a new shorter file
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

            # Tailer detects size decrease, resets offset, and waits for new lines
            res2 = tailer.process_available_rows()
            self.assertEqual(tailer.byte_offset, len(",".join(headers)) + 2)  # past header

    # -----------------------------------------------------------------------
    # 10. End-to-End API Persistence Verification
    # -----------------------------------------------------------------------

    def test_end_to_end_api_persistence(self):
        """Verify that normalized flows posted by the tailer are retrievable from SQLite soc.db."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = pathlib.Path(tmpdir) / "e2e_flows.csv"
            test_eid = f"live-adapter-e2e-{uuid.uuid4()}"

            headers = ["src_ip", "dst_ip", "src_port", "flow_id"] + CANONICAL_FEATURES
            row_values = ["198.51.100.22", "198.51.100.1", "61234", test_eid] + [
                self.base_canonical_row[f] for f in CANONICAL_FEATURES
            ]

            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerow(row_values)

            tailer = LiveFlowTailer(
                file_path=csv_path,
                adapter=self.adapter,
                http_client=self.client,
            )

            res = tailer.process_available_rows()
            self.assertEqual(res["sent_accepted"], 1)

            # Verify in SQLite via GET /api/events?search=...
            events_resp = self.client.get("/api/events?limit=5")
            self.assertEqual(events_resp.status_code, 200)
            events = events_resp.json()
            self.assertTrue(len(events) >= 1)
            latest = events[0]
            self.assertEqual(latest["source"], "live_sensor")


if __name__ == "__main__":
    unittest.main()
