"""
agents/threat_intelligence/config.py
====================================
Configuration and constants for Stage 11 Threat Intelligence Enrichment.

Multi-Agent SOC Project -- Stage 11
"""

import os
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Agent Identity
# ---------------------------------------------------------------------------
AGENT_NAME = "Threat Intelligence Agent"
AGENT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Verdict Taxonomy (Requirement 7)
# ---------------------------------------------------------------------------
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_NO_KNOWN_REPORTS = "NO_KNOWN_REPORTS"
VERDICT_UNKNOWN = "UNKNOWN/UNAVAILABLE"

VALID_VERDICTS = {
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_NO_KNOWN_REPORTS,
    VERDICT_UNKNOWN,
}

# ---------------------------------------------------------------------------
# Supported Providers (Requirement 3 & 4)
# ---------------------------------------------------------------------------
PROVIDER_MOCK = "MockProvider"
PROVIDER_ABUSEIPDB = "AbuseIPDB"
PROVIDER_VIRUSTOTAL = "VirusTotal"

# Environment Variable Names for Secrets (never logged or hardcoded)
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"

# Cache Configuration
DEFAULT_CACHE_TTL_SECONDS = 86400  # 24 hours
REQUEST_TIMEOUT_SECONDS = 5.0

# ---------------------------------------------------------------------------
# Explicit Disclaimers (Requirement 4 & 7)
# ---------------------------------------------------------------------------
NO_KNOWN_REPORTS_DISCLAIMER = (
    "Notice: 'NO_KNOWN_REPORTS' indicates that no prior abuse reports or detections exist in the queried "
    "intelligence source. It does NOT guarantee that the indicator is safe or benign."
)

MOCK_DATA_DISCLAIMER = (
    "[MOCK / DEMO DATA - NOT REAL INTELLIGENCE] Results are simulated fixtures for offline demonstrations "
    "and test runs. No external lookup was performed."
)

# ---------------------------------------------------------------------------
# Well-known Port Intelligence / Service Signatures
# Contextual enrichment for ports when IP indicators are absent or accompanied
# ---------------------------------------------------------------------------
KNOWN_PORT_CONTEXT = {
    21: {"service": "FTP", "risk_note": "Legacy cleartext file transfer protocol; frequent brute-force target."},
    22: {"service": "SSH", "risk_note": "Secure Shell remote access; high-frequency credential stuffing target."},
    23: {"service": "Telnet", "risk_note": "Unencrypted legacy protocol; commonly scanned by IoT botnets (e.g., Mirai)."},
    25: {"service": "SMTP", "risk_note": "Simple Mail Transfer Protocol; prone to spam relay and phishing enumeration."},
    53: {"service": "DNS", "risk_note": "Domain Name System; vector for DNS tunneling, amplification, and cache poisoning."},
    80: {"service": "HTTP", "risk_note": "Unencrypted web transport; target for web application attacks and scanners."},
    110: {"service": "POP3", "risk_note": "Post Office Protocol v3; legacy unencrypted mail access."},
    135: {"service": "MSRPC", "risk_note": "Microsoft RPC Endpoint Mapper; target for remote code execution exploits."},
    139: {"service": "NetBIOS", "risk_note": "Legacy Windows file sharing; frequent lateral movement vector."},
    443: {"service": "HTTPS", "risk_note": "Encrypted web traffic; legitimate services and encrypted C2 channels."},
    445: {"service": "SMB", "risk_note": "Server Message Block; critical vector for WannaCry, EternalBlue, and lateral propagation."},
    1433: {"service": "MSSQL", "risk_note": "Microsoft SQL Server database listener; brute-force target."},
    3306: {"service": "MySQL", "risk_note": "MySQL database listener; unauthorized remote access target."},
    3389: {"service": "RDP", "risk_note": "Remote Desktop Protocol; high-priority target for ransomware and credential brute-forcing."},
    4444: {"service": "Metasploit Default Listener", "risk_note": "Common default port for Metasploit payload listeners and backdoors."},
    8080: {"service": "HTTP-Proxy / Alternate Web", "risk_note": "Alternative HTTP port; frequently used by web application servers."},
    8443: {"service": "HTTPS-Alt", "risk_note": "Alternative SSL/TLS web administration interface."},
}

# ---------------------------------------------------------------------------
# Log Paths
# ---------------------------------------------------------------------------
THREAT_INTEL_LOG_FILE = PROJECT_ROOT / "logs" / "threat_intel.json"
THREAT_INTEL_RUNTIME_LOG = PROJECT_ROOT / "logs" / "threat_intel_runtime.log"
