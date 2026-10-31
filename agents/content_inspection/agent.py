"""
agents/content_inspection/agent.py
==================================
Content & Context Inspection Agent.

Multi-Agent SOC Project

Analyzes data transfer events, file access metadata, process context,
and destination indicators to distinguish genuine user high-volume operations
(backups, media syncs, dev operations) from malicious data exfiltration.
"""

import datetime
import logging
import os
import pathlib
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from agents.content_inspection.config import (
    AGENT_NAME,
    CRITICAL_SENSITIVE_EXTENSIONS,
    CRITICAL_SENSITIVE_FILES,
    LEGITIMATE_TRANSFER_PROCESSES,
    ROUTINE_BENIGN_EXTENSIONS,
    RUNTIME_LOG,
    SUSPICIOUS_TRANSFER_PROCESSES,
    TRUSTED_DESTINATIONS,
    VERDICT_BENIGN_ROUTINE,
    VERDICT_EXFILTRATION_CRITICAL,
    VERDICT_GENUINE_USER_HIGH_VOLUME,
    VERDICT_SUSPICIOUS_UNVERIFIED,
)

logger = logging.getLogger("SOC.ContentInspection")
if not logger.handlers:
    RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)

# High volume threshold: flows > 10MB or packet rates exceeding interactive thresholds
HIGH_VOLUME_BYTES_THRESHOLD = 5 * 1024 * 1024  # 5 MB


class ContentInspectionAgent:
    """
    Evaluates transfer context, content sensitivity, process lineage, and
    destination reputation to differentiate genuine high-volume network transfers
    from malicious data exfiltration.
    """

    def __init__(self):
        self.agent_name = AGENT_NAME

    def inspect_transfer(
        self,
        event_id: str,
        files: Optional[List[str]] = None,
        process_name: Optional[str] = None,
        command_line: Optional[str] = None,
        user: Optional[str] = None,
        destination: Optional[str] = None,
        volume_bytes: Optional[int] = None,
        flow_features: Optional[Dict[str, Any]] = None,
        preceding_compromise: bool = False,
        threat_intel_reputation: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Deeply inspect a file transmission or high-volume network flow.

        Args:
            event_id: Unique event identifier.
            files: List of file paths, filenames, or archives transferred/accessed.
            process_name: Initiating process binary name (e.g., 'rsync', 'curl', 'python3').
            command_line: Full command line string if available from host logs.
            user: Operating system user initiating the action.
            destination: Destination IP or hostname.
            volume_bytes: Total bytes transferred if known.
            flow_features: 78-feature dictionary if inspecting a network flow.
            preceding_compromise: Whether preceding attack stages occurred on this host.
            threat_intel_reputation: Threat intel reputation score (0.0=malicious, 1.0=clean).

        Returns:
            Structured inspection report dictionary.
        """
        now = datetime.datetime.now().isoformat()
        files = files or []

        # Derive volume if not provided directly
        if volume_bytes is None and flow_features:
            fwd_byts = flow_features.get("TotLen Fwd Pkts") or flow_features.get("Subflow Fwd Byts")
            bwd_byts = flow_features.get("TotLen Bwd Pkts") or flow_features.get("Subflow Bwd Byts")
            volume_bytes = int((fwd_byts or 0) + (bwd_byts or 0))

        # Check for extracted files inside command_line if files list empty
        extracted_files = list(files)
        if command_line and not extracted_files:
            extracted_files.extend(self._extract_files_from_command(command_line))

        # 1. Content & File Sensitivity Evaluation
        sensitive_matches, benign_matches = self._classify_files(extracted_files, command_line)
        has_sensitive_files = len(sensitive_matches) > 0
        has_benign_files = len(benign_matches) > 0

        # 2. Process Lineage & Binary Evaluation
        proc_verdict, proc_reason = self._evaluate_process(process_name, command_line, user)

        # 3. Destination Evaluation
        dest_verdict, dest_reason = self._evaluate_destination(destination, threat_intel_reputation)

        # 4. Volumetric Assessment
        is_high_volume = (volume_bytes or 0) >= HIGH_VOLUME_BYTES_THRESHOLD
        if not is_high_volume and flow_features:
            flow_byts_s = flow_features.get("Flow Byts/s")
            if flow_byts_s and flow_byts_s > 500_000:
                is_high_volume = True

        # 5. Core Decision Logic Synthesizing Context
        findings = []
        is_attack = False
        confidence = 0.85

        if has_sensitive_files:
            # Sensitive system or credential files targeted
            findings.append(f"CRITICAL SENSITIVE CONTENT IDENTIFIED: {', '.join(sensitive_matches)}.")
            if proc_verdict == "SUSPICIOUS":
                findings.append(f"Suspicious transfer process used: {proc_reason}.")
            if preceding_compromise:
                findings.append("Context Correlation: Host has prior unauthenticated compromise or privilege escalation.")

            verdict = VERDICT_EXFILTRATION_CRITICAL
            is_attack = True
            confidence = 0.95
            explanation = (
                f"Data exfiltration confirmed: Critical sensitive data ({', '.join(sensitive_matches)}) "
                f"targeted for transmission by process '{process_name or 'unknown'}'."
            )

        elif preceding_compromise and is_high_volume and proc_verdict != "LEGITIMATE":
            # High volume after recent compromise by unverified process
            findings.append("High volume outbound transmission observed immediately following host compromise.")
            verdict = VERDICT_EXFILTRATION_CRITICAL
            is_attack = True
            confidence = 0.90
            explanation = (
                f"Likely exfiltration: Host has active compromise indicators and transmitted "
                f"{volume_bytes or 0} bytes via unverified process '{process_name or 'untracked'}'."
            )

        elif is_high_volume and proc_verdict == "LEGITIMATE" and not preceding_compromise:
            # Genuine User / System Operation with high volume
            findings.append(f"High data volume ({volume_bytes or 0} bytes) verified as genuine user/system activity.")
            findings.append(f"Process verification: {proc_reason}.")
            findings.append(f"Destination profile: {dest_reason}.")
            if has_benign_files:
                findings.append(f"Routine benign file formats identified: {', '.join(benign_matches)}.")

            verdict = VERDICT_GENUINE_USER_HIGH_VOLUME
            is_attack = False
            confidence = 0.92
            explanation = (
                f"Genuine high-volume transfer: Legitimate process '{process_name or command_line}' "
                f"transmitting routine non-sensitive content without preceding compromise indicators."
            )

        elif is_high_volume and dest_verdict == "TRUSTED" and not preceding_compromise:
            # High volume directed to known trusted repository / cloud
            findings.append(f"High data volume ({volume_bytes or 0} bytes) transmitted to verified trusted destination.")
            findings.append(f"Destination verification: {dest_reason}.")
            verdict = VERDICT_GENUINE_USER_HIGH_VOLUME
            is_attack = False
            confidence = 0.88
            explanation = (
                f"Genuine high-volume operation: Data sent to trusted infrastructure ({destination}) "
                f"with zero sensitive credentials or compromise indicators."
            )

        elif proc_verdict == "SUSPICIOUS":
            findings.append(f"Suspicious transmission utility invoked: {proc_reason}.")
            if dest_verdict == "SUSPICIOUS":
                findings.append(f"Untrusted or malicious destination endpoint: {dest_reason}.")
                verdict = VERDICT_EXFILTRATION_CRITICAL
                is_attack = True
                confidence = 0.90
                explanation = "Suspicious exfiltration tool transmitting to untrusted/malicious endpoint."
            else:
                verdict = VERDICT_SUSPICIOUS_UNVERIFIED
                is_attack = False
                confidence = 0.75
                explanation = f"Unusual utility '{process_name}' transmitting data; manual analyst verification required."

        elif not is_high_volume and not has_sensitive_files:
            verdict = VERDICT_BENIGN_ROUTINE
            is_attack = False
            confidence = 0.95
            explanation = "Routine low-volume network flow with no sensitive indicators."

        else:
            verdict = VERDICT_SUSPICIOUS_UNVERIFIED
            is_attack = False
            confidence = 0.70
            explanation = "High-volume transfer with indeterminate process lineage; flagged for surveillance."

        report = {
            "inspection_id": str(uuid.uuid4()),
            "event_id": event_id,
            "timestamp": now,
            "verdict": verdict,
            "is_attack": is_attack,
            "confidence": round(confidence, 4),
            "is_high_volume": is_high_volume,
            "volume_bytes": volume_bytes or 0,
            "sensitive_matches": sensitive_matches,
            "benign_matches": benign_matches,
            "process_evaluation": {
                "process_name": process_name,
                "user": user,
                "status": proc_verdict,
                "details": proc_reason,
            },
            "destination_evaluation": {
                "destination": destination,
                "status": dest_verdict,
                "details": dest_reason,
            },
            "findings": findings,
            "explanation": explanation,
        }

        logger.info(
            "Inspected event %s: verdict=%s is_attack=%s volume=%s bytes",
            event_id, verdict, is_attack, volume_bytes,
        )
        return report

    def _classify_files(
        self, files: List[str], command_line: Optional[str] = None
    ) -> Tuple[List[str], List[str]]:
        """Identify sensitive credentials or routine benign extensions."""
        sensitive = set()
        benign = set()

        text_to_scan = " ".join(files)
        if command_line:
            text_to_scan += f" {command_line}"

        text_lower = text_to_scan.lower()

        # Check critical exact filenames
        for crit in CRITICAL_SENSITIVE_FILES:
            if crit.lower() in text_lower:
                sensitive.add(crit)

        # Check critical extensions
        for ext in CRITICAL_SENSITIVE_EXTENSIONS:
            if ext in text_lower:
                sensitive.add(f"*{ext}")

        # Check benign extensions
        for b_ext in ROUTINE_BENIGN_EXTENSIONS:
            if b_ext in text_lower:
                benign.add(f"*{b_ext}")

        return sorted(list(sensitive)), sorted(list(benign))

    def _evaluate_process(
        self,
        process_name: Optional[str],
        command_line: Optional[str],
        user: Optional[str],
    ) -> Tuple[str, str]:
        """Classify process lineage."""
        p_name = (process_name or "").lower().strip()
        cmd = (command_line or "").lower().strip()
        full = f"{p_name} {cmd}".strip()

        # Check legitimate processes first with word boundary
        for l_proc in LEGITIMATE_TRANSFER_PROCESSES:
            pattern = rf"\b{re.escape(l_proc)}\b"
            if re.search(pattern, full) or p_name == l_proc:
                return "LEGITIMATE", f"Matches authorized backup/development utility: '{l_proc}'"

        # Check suspicious processes with word boundary
        for s_proc in SUSPICIOUS_TRANSFER_PROCESSES:
            pattern = rf"\b{re.escape(s_proc)}\b"
            if re.search(pattern, full) or p_name == s_proc:
                return "SUSPICIOUS", f"Matches suspicious exfiltration/reverse shell utility: '{s_proc}'"

        if user in ("www-data", "nobody") and any(
            re.search(rf"\b{tok}\b", full) for tok in ["curl", "python", "python3", "sh", "bash"]
        ):
            return "SUSPICIOUS", f"Web daemon '{user}' executing interactive transfer command"

        return "NEUTRAL", "Standard user or system process"

    def _evaluate_destination(
        self, destination: Optional[str], threat_intel_reputation: Optional[float]
    ) -> Tuple[str, str]:
        """Classify destination endpoint."""
        if not destination:
            return "UNKNOWN", "No destination IP or hostname provided"

        dest_lower = destination.lower()
        for trusted in TRUSTED_DESTINATIONS:
            if trusted in dest_lower:
                return "TRUSTED", f"Destination matches verified trusted domain '{trusted}'"

        if threat_intel_reputation is not None:
            if threat_intel_reputation < 0.40:
                return "SUSPICIOUS", f"Threat intelligence flagged destination with low reputation ({threat_intel_reputation:.2f})"
            elif threat_intel_reputation > 0.80:
                return "TRUSTED", f"Threat intelligence confirmed clean reputation ({threat_intel_reputation:.2f})"

        return "NEUTRAL", f"Destination '{destination}' requires general monitoring"

    def _extract_files_from_command(self, cmd: str) -> List[str]:
        """Extract path-like strings and files from command line."""
        tokens = cmd.split()
        extracted = []
        for token in tokens:
            cleaned = token.strip("\",';")
            if "/" in cleaned or "\\" in cleaned or "." in cleaned:
                extracted.append(cleaned)
        return extracted
