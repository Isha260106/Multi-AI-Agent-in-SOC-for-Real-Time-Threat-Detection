"""
agents/threat_intelligence/providers.py
=======================================
Threat Intelligence Provider Interface and Implementations.

Multi-Agent SOC Project -- Stage 11

PROVIDERS:
  - BaseIntelProvider: Abstract interface.
  - MockIntelProvider: Local deterministic mock fixtures for offline / demo mode.
  - AbuseIPDBProvider: Optional real-time lookup via AbuseIPDB v2 API.
  - VirusTotalProvider: Optional real-time lookup via VirusTotal v3 API.

SECURITY AND INTEGRITY:
  - API keys read strictly from environment variables (never hardcoded, never logged).
  - Rate limits, timeouts, connection errors, and missing keys handled gracefully.
  - Mock fixtures strictly labeled with MOCK_DATA_DISCLAIMER (is_mock=True).
  - "NO_KNOWN_REPORTS" explicitly carries the disclaimer that it is not guaranteed safe.
"""

import abc
import datetime
import json
import logging
import os
import re
import socket
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from agents.threat_intelligence.config import (
    ABUSEIPDB_API_KEY_ENV,
    DEFAULT_CACHE_TTL_SECONDS,
    KNOWN_PORT_CONTEXT,
    MOCK_DATA_DISCLAIMER,
    NO_KNOWN_REPORTS_DISCLAIMER,
    PROVIDER_ABUSEIPDB,
    PROVIDER_MOCK,
    PROVIDER_VIRUSTOTAL,
    REQUEST_TIMEOUT_SECONDS,
    THREAT_INTEL_RUNTIME_LOG,
    VERDICT_MALICIOUS,
    VERDICT_NO_KNOWN_REPORTS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    VIRUSTOTAL_API_KEY_ENV,
)

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("SOC.ThreatIntel.Providers")
if not logger.handlers:
    THREAT_INTEL_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(THREAT_INTEL_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


# IP validation pattern (IPv4)
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


PRIVATE_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def is_private_or_internal_ip(ip_str: str) -> bool:
    """
    Check if an IPv4/IPv6 string is a private RFC 1918, loopback, or link-local address
    that must never be sent to external threat intelligence providers.
    """
    clean = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
        return any(ip_obj in net for net in PRIVATE_INTERNAL_NETWORKS)
    except ValueError:
        return False


# ===========================================================================
# Base Provider Interface
# ===========================================================================
class BaseIntelProvider(abc.ABC):
    """Abstract base class for all threat intelligence providers."""

    def __init__(self, name: str, cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        self.name = name
        self.cache_ttl_seconds = cache_ttl_seconds

    @abc.abstractmethod
    def lookup(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """
        Perform intelligence lookup for an indicator.

        Args:
            indicator_type: 'ip', 'port', etc.
            indicator_value: The observable value string.

        Returns:
            Dictionary matching the standard threat intelligence lookup schema.
        """
        pass

    def _calc_expiration(self, seconds: Optional[int] = None) -> Tuple[str, str]:
        """Calculate ISO timestamps for last_checked and expires_at."""
        ttl = seconds if seconds is not None else self.cache_ttl_seconds
        now = datetime.datetime.now()
        last_checked = now.isoformat()
        expires_at = (now + datetime.timedelta(seconds=ttl)).isoformat()
        return last_checked, expires_at

    def _create_private_ip_result(self, clean_val: str) -> Dict[str, Any]:
        """Return a standardized local result for private RFC 1918 or internal addresses."""
        last_checked, expires_at = self._calc_expiration(86400 * 7)  # 7-day cache
        return {
            "indicator_type": "ip",
            "indicator_value": clean_val,
            "provider": "LocalPrivateIPClassifier",
            "verdict": VERDICT_NO_KNOWN_REPORTS,
            "reputation_score": 0.0,
            "evidence_links": [],
            "raw_response": {
                "status": "internal_reserved",
                "is_private": True,
                "note": "RFC 1918 / Loopback / Link-Local / Reserved private IP address",
            },
            "last_checked": last_checked,
            "expires_at": expires_at,
            "is_mock": False,
            "limitations": [
                "Address is an internal / private network IP (RFC 1918 / link-local / loopback). "
                "External threat intelligence queries were omitted to prevent internal network topology disclosure."
            ],
        }


# ===========================================================================
# Mock Provider (Offline / Demo Fixtures)
# ===========================================================================
class MockIntelProvider(BaseIntelProvider):
    """
    Deterministic offline mock intelligence provider.
    Always flags results with is_mock=True and adds MOCK_DATA_DISCLAIMER.
    Never presents mock intelligence as real external intelligence.
    """

    MOCK_IP_FIXTURES: Dict[str, Dict[str, Any]] = {
        # Malicious IP fixtures
        "198.51.100.1": {
            "verdict": VERDICT_MALICIOUS,
            "reputation_score": 98.0,
            "reports_count": 142,
            "categories": ["Botnet", "SSH Brute-Force", "Port Scanner"],
            "links": ["https://mock.threatintel.local/ip/198.51.100.1"],
            "notes": "Known high-confidence malicious host participating in active scanning and credential stuffing.",
        },
        "185.220.101.5": {
            "verdict": VERDICT_MALICIOUS,
            "reputation_score": 92.0,
            "reports_count": 89,
            "categories": ["Tor Exit Node", "Credential Brute-Force"],
            "links": ["https://mock.threatintel.local/ip/185.220.101.5"],
            "notes": "Known malicious Tor exit node exhibiting probing behavior.",
        },
        # Suspicious IP fixtures
        "198.51.100.2": {
            "verdict": VERDICT_SUSPICIOUS,
            "reputation_score": 42.0,
            "reports_count": 14,
            "categories": ["Suspicious Activity", "Port Probe"],
            "links": ["https://mock.threatintel.local/ip/198.51.100.2"],
            "notes": "Low-to-moderate frequency connection attempts reported in the last 30 days.",
        },
        # Clean / Unreported IP fixtures
        "8.8.8.8": {
            "verdict": VERDICT_NO_KNOWN_REPORTS,
            "reputation_score": 0.0,
            "reports_count": 0,
            "categories": ["Public Resolver / Anycast"],
            "links": ["https://mock.threatintel.local/ip/8.8.8.8"],
            "notes": "Google Public DNS. Zero historical malicious abuse reports.",
        },
        "1.1.1.1": {
            "verdict": VERDICT_NO_KNOWN_REPORTS,
            "reputation_score": 0.0,
            "reports_count": 0,
            "categories": ["Public Resolver / Anycast"],
            "links": ["https://mock.threatintel.local/ip/1.1.1.1"],
            "notes": "Cloudflare DNS. Zero historical malicious abuse reports.",
        },
        "198.51.100.3": {
            "verdict": VERDICT_NO_KNOWN_REPORTS,
            "reputation_score": 0.0,
            "reports_count": 0,
            "categories": [],
            "links": ["https://mock.threatintel.local/ip/198.51.100.3"],
            "notes": "No public abuse reports recorded for this indicator.",
        },
    }

    def __init__(self, cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        super().__init__(name=PROVIDER_MOCK, cache_ttl_seconds=cache_ttl_seconds)

    def lookup(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        last_checked, expires_at = self._calc_expiration()
        clean_type = indicator_type.strip().lower()
        clean_val = indicator_value.strip()

        limitations = [MOCK_DATA_DISCLAIMER]

        # IP Lookups
        if clean_type == "ip":
            if is_private_or_internal_ip(clean_val) and clean_val not in self.MOCK_IP_FIXTURES:
                return self._create_private_ip_result(clean_val)
            fixture = self.MOCK_IP_FIXTURES.get(clean_val)
            if fixture:
                verdict = fixture["verdict"]
                score = fixture["reputation_score"]
                links = fixture["links"]
                raw_response = {
                    "mock_fixture": True,
                    "indicator": clean_val,
                    "details": fixture,
                    "disclaimer": MOCK_DATA_DISCLAIMER,
                }
                if verdict == VERDICT_NO_KNOWN_REPORTS:
                    limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)
            else:
                # Default for unmapped IP in mock mode: NO_KNOWN_REPORTS
                verdict = VERDICT_NO_KNOWN_REPORTS
                score = 0.0
                links = [f"https://mock.threatintel.local/ip/{clean_val}"]
                raw_response = {
                    "mock_fixture": True,
                    "indicator": clean_val,
                    "note": "Unmapped IP in mock database; default benign test fixture.",
                }
                limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": verdict,
                "reputation_score": score,
                "evidence_links": links,
                "raw_response": raw_response,
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": True,
                "limitations": limitations,
            }

        # Port Lookups
        if clean_type == "port":
            try:
                port_num = int(float(clean_val))
            except (ValueError, TypeError):
                port_num = None

            port_info = KNOWN_PORT_CONTEXT.get(port_num) if port_num else None
            if port_num in (4444, 135, 139, 445):
                verdict = VERDICT_SUSPICIOUS
                score = 65.0
            elif port_num in (21, 22, 23, 3389):
                verdict = VERDICT_SUSPICIOUS
                score = 45.0
            else:
                verdict = VERDICT_NO_KNOWN_REPORTS
                score = None

            if verdict == VERDICT_NO_KNOWN_REPORTS:
                limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

            links = [f"https://www.speedguide.net/port.php?port={clean_val}"] if port_num else []
            raw_response = {
                "mock_fixture": True,
                "port": port_num,
                "context": port_info or {"service": "Unassigned/Ephemeral", "risk_note": "General traffic port."},
            }

            return {
                "indicator_type": "port",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": verdict,
                "reputation_score": score,
                "evidence_links": links,
                "raw_response": raw_response,
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": True,
                "limitations": limitations,
            }

        # Fallback for other indicator types
        return {
            "indicator_type": clean_type,
            "indicator_value": clean_val,
            "provider": self.name,
            "verdict": VERDICT_UNKNOWN,
            "reputation_score": None,
            "evidence_links": [],
            "raw_response": {"mock_fixture": True, "error": f"Unsupported indicator type: {clean_type}"},
            "last_checked": last_checked,
            "expires_at": expires_at,
            "is_mock": True,
            "limitations": limitations + [f"Mock provider does not index indicator type '{clean_type}'."],
        }


# ===========================================================================
# AbuseIPDB Provider (Real External API)
# ===========================================================================
class AbuseIPDBProvider(BaseIntelProvider):
    """
    AbuseIPDB Threat Intelligence Provider.
    Queries the official AbuseIPDB v2 Check endpoint.
    API key is read strictly from ABUSEIPDB_API_KEY environment variable.
    """

    API_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        super().__init__(name=PROVIDER_ABUSEIPDB, cache_ttl_seconds=cache_ttl_seconds)

    def _get_api_key(self) -> Optional[str]:
        """Read API key securely from environment."""
        key = os.environ.get(ABUSEIPDB_API_KEY_ENV, "").strip()
        return key if key else None

    def lookup(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        last_checked, expires_at = self._calc_expiration()
        clean_type = indicator_type.strip().lower()
        clean_val = indicator_value.strip()

        # AbuseIPDB only supports IP addresses
        if clean_type != "ip":
            return {
                "indicator_type": clean_type,
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": "AbuseIPDB only supports IP indicator lookups."},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"AbuseIPDB does not support indicator type '{clean_type}'."],
            }

        # RFC 1918 / Internal IP Protection
        if is_private_or_internal_ip(clean_val):
            return self._create_private_ip_result(clean_val)

        # Check API key configuration
        api_key = self._get_api_key()
        if not api_key:
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"status": "unconfigured", "error": "API key missing"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [
                    f"AbuseIPDB API key not configured in environment variable '{ABUSEIPDB_API_KEY_ENV}'.",
                    "Real lookup skipped. External lookups are optional.",
                ],
            }

        # Validate IP format before querying
        if not IPV4_REGEX.match(clean_val):
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": "Invalid IPv4 address format."},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"Value '{clean_val}' is not a valid IPv4 address."],
            }

        params = urllib.parse.urlencode({"ipAddress": clean_val, "maxAgeInDays": "90", "verbose": ""})
        url = f"{self.API_ENDPOINT}?{params}"
        req = urllib.request.Request(
            url,
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "Multi-Agent-SOC/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                status_code = resp.getcode()
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8")).get("data", {})

            # Extract metrics
            abuse_score = float(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            country_code = data.get("countryCode")
            isp = data.get("isp")
            domain = data.get("domain")

            limitations = []
            if abuse_score >= 50.0:
                verdict = VERDICT_MALICIOUS
            elif abuse_score > 0.0 or total_reports > 0:
                verdict = VERDICT_SUSPICIOUS
            else:
                verdict = VERDICT_NO_KNOWN_REPORTS
                limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

            evidence_links = [f"https://www.abuseipdb.com/check/{clean_val}"]

            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": verdict,
                "reputation_score": abuse_score,
                "evidence_links": evidence_links,
                "raw_response": {
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": total_reports,
                    "countryCode": country_code,
                    "isp": isp,
                    "domain": domain,
                    "isWhitelisted": data.get("isWhitelisted", False),
                    "lastReportedAt": data.get("lastReportedAt"),
                },
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": limitations,
            }

        except urllib.error.HTTPError as err:
            logger.warning("AbuseIPDB HTTPError for IP %s: HTTP %s", clean_val, err.code)
            if err.code == 429:
                limitation = "AbuseIPDB daily rate limit exceeded (HTTP 429). Retry after quota resets."
            elif err.code in (401, 403):
                limitation = f"AbuseIPDB authentication rejected (HTTP {err.code}). Verify API key permissions."
            elif err.code == 422:
                limitation = "AbuseIPDB unprocessable entity (HTTP 422). IP address could not be parsed."
            else:
                limitation = f"AbuseIPDB service returned HTTP error {err.code}."

            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"http_status": err.code, "error": str(err)},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [limitation],
            }

        except (urllib.error.URLError, socket.timeout, TimeoutError) as err:
            logger.warning("AbuseIPDB network failure for IP %s: %s", clean_val, err)
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": f"Network error or timeout: {str(err)}"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": ["AbuseIPDB network request timed out or connection refused."],
            }

        except Exception as exc:
            logger.error("Unexpected error querying AbuseIPDB for IP %s: %s", clean_val, exc)
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": f"Unexpected error: {str(exc)}"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"Unexpected error processing AbuseIPDB response: {str(exc)}"],
            }


# ===========================================================================
# VirusTotal Provider (Real External API)
# ===========================================================================
class VirusTotalProvider(BaseIntelProvider):
    """
    VirusTotal Threat Intelligence Provider.
    Queries the official VirusTotal v3 IP Addresses API.
    API key is read strictly from VIRUSTOTAL_API_KEY environment variable.
    """

    API_BASE = "https://www.virustotal.com/api/v3/ip_addresses"

    def __init__(self, cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        super().__init__(name=PROVIDER_VIRUSTOTAL, cache_ttl_seconds=cache_ttl_seconds)

    def _get_api_key(self) -> Optional[str]:
        """Read API key securely from environment."""
        key = os.environ.get(VIRUSTOTAL_API_KEY_ENV, "").strip()
        return key if key else None

    def lookup(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        last_checked, expires_at = self._calc_expiration()
        clean_type = indicator_type.strip().lower()
        clean_val = indicator_value.strip()

        if clean_type != "ip":
            return {
                "indicator_type": clean_type,
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": "VirusTotal provider only supports IP indicator lookups."},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"VirusTotal provider does not index indicator type '{clean_type}'."],
            }

        # RFC 1918 / Internal IP Protection
        if is_private_or_internal_ip(clean_val):
            return self._create_private_ip_result(clean_val)

        api_key = self._get_api_key()
        if not api_key:
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"status": "unconfigured", "error": "API key missing"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [
                    f"VirusTotal API key not configured in environment variable '{VIRUSTOTAL_API_KEY_ENV}'.",
                    "Real lookup skipped. External lookups are optional.",
                ],
            }

        if not IPV4_REGEX.match(clean_val):
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": "Invalid IPv4 address format."},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"Value '{clean_val}' is not a valid IPv4 address."],
            }

        url = f"{self.API_BASE}/{clean_val}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "Multi-Agent-SOC/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                raw_bytes = resp.read()
                payload = json.loads(raw_bytes.decode("utf-8"))
                attributes = payload.get("data", {}).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))
            harmless_count = int(stats.get("harmless", 0))
            undetected_count = int(stats.get("undetected", 0))

            limitations = []
            if malicious_count >= 3:
                verdict = VERDICT_MALICIOUS
            elif malicious_count > 0 or suspicious_count > 0:
                verdict = VERDICT_SUSPICIOUS
            else:
                verdict = VERDICT_NO_KNOWN_REPORTS
                limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

            evidence_links = [f"https://www.virustotal.com/gui/ip-address/{clean_val}"]

            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": verdict,
                "reputation_score": float(malicious_count),
                "evidence_links": evidence_links,
                "raw_response": {
                    "last_analysis_stats": stats,
                    "as_owner": attributes.get("as_owner"),
                    "country": attributes.get("country"),
                    "reputation": attributes.get("reputation"),
                },
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": limitations,
            }

        except urllib.error.HTTPError as err:
            logger.warning("VirusTotal HTTPError for IP %s: HTTP %s", clean_val, err.code)
            if err.code == 429:
                limitation = "VirusTotal rate limit exceeded (HTTP 429). Public API permits 4 reqs/min."
            elif err.code in (401, 403):
                limitation = f"VirusTotal authentication failure (HTTP {err.code}). Verify API key."
            elif err.code == 404:
                # 404 in VT means IP address not known in VT dataset
                last_checked, expires_at = self._calc_expiration()
                return {
                    "indicator_type": "ip",
                    "indicator_value": clean_val,
                    "provider": self.name,
                    "verdict": VERDICT_NO_KNOWN_REPORTS,
                    "reputation_score": 0.0,
                    "evidence_links": [f"https://www.virustotal.com/gui/ip-address/{clean_val}"],
                    "raw_response": {"message": "IP address not found in VirusTotal dataset."},
                    "last_checked": last_checked,
                    "expires_at": expires_at,
                    "is_mock": False,
                    "limitations": [NO_KNOWN_REPORTS_DISCLAIMER],
                }
            else:
                limitation = f"VirusTotal service returned HTTP error {err.code}."

            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"http_status": err.code, "error": str(err)},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [limitation],
            }

        except (urllib.error.URLError, socket.timeout, TimeoutError) as err:
            logger.warning("VirusTotal network failure for IP %s: %s", clean_val, err)
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": f"Network error or timeout: {str(err)}"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": ["VirusTotal network request timed out or connection refused."],
            }

        except Exception as exc:
            logger.error("Unexpected error querying VirusTotal for IP %s: %s", clean_val, exc)
            return {
                "indicator_type": "ip",
                "indicator_value": clean_val,
                "provider": self.name,
                "verdict": VERDICT_UNKNOWN,
                "reputation_score": None,
                "evidence_links": [],
                "raw_response": {"error": f"Unexpected error: {str(exc)}"},
                "last_checked": last_checked,
                "expires_at": expires_at,
                "is_mock": False,
                "limitations": [f"Unexpected error processing VirusTotal response: {str(exc)}"],
            }
