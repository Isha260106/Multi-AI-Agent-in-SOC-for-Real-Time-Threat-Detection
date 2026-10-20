"""
agents/threat_intelligence/agent.py
===================================
Modular Threat Intelligence Enrichment Agent (Stage 11).

Multi-Agent SOC Project -- Stage 11

KEY RESPONSIBILITIES:
  1. Extract observable indicators (IPs, ports, protocols, timestamps) without inventing data.
  2. Perform lookups through modular providers (AbuseIPDB, VirusTotal, MockProvider).
  3. Cache lookups in SQLite with timestamps and TTL expiration. Avoid repeated requests.
  4. Enrich investigation reports and event profiles non-destructively.
  5. Strictly distinguish MALICIOUS, SUSPICIOUS, NO_KNOWN_REPORTS, and UNKNOWN/UNAVAILABLE.
  6. Flag mock results with [MOCK / DEMO DATA - NOT REAL INTELLIGENCE].
"""

import copy
import datetime
import json
import logging
import os
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_intelligence.config import (
    ABUSEIPDB_API_KEY_ENV,
    AGENT_NAME,
    AGENT_VERSION,
    DEFAULT_CACHE_TTL_SECONDS,
    MOCK_DATA_DISCLAIMER,
    NO_KNOWN_REPORTS_DISCLAIMER,
    PROVIDER_ABUSEIPDB,
    PROVIDER_MOCK,
    PROVIDER_VIRUSTOTAL,
    THREAT_INTEL_LOG_FILE,
    THREAT_INTEL_RUNTIME_LOG,
    VERDICT_MALICIOUS,
    VERDICT_NO_KNOWN_REPORTS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    VIRUSTOTAL_API_KEY_ENV,
)
from agents.threat_intelligence.providers import (
    BaseIntelProvider,
    IPV4_REGEX,
    MockIntelProvider,
    AbuseIPDBProvider,
    VirusTotalProvider,
)
from storage.config import DB_PATH
from storage.db import AlertStore
from storage.query import ThreatIntelQueryStore

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("SOC.ThreatIntelligence")
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


# ===========================================================================
# Threat Intelligence Agent
# ===========================================================================
class ThreatIntelligenceAgent:
    """
    Threat Intelligence Agent responsible for observable indicator extraction,
    cached provider lookups, and non-destructive investigation report enrichment.
    """

    def __init__(
        self,
        default_provider: Optional[BaseIntelProvider] = None,
        db_path: pathlib.Path = DB_PATH,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        offline_mode: bool = False,
        log_to_file: bool = True,
    ):
        self._db_path = db_path
        self._cache_ttl_seconds = cache_ttl_seconds
        self._offline_mode = offline_mode
        self._log_to_file = log_to_file

        # Initialize provider registry
        self._providers: Dict[str, BaseIntelProvider] = {
            PROVIDER_MOCK.lower(): MockIntelProvider(cache_ttl_seconds=cache_ttl_seconds),
            PROVIDER_ABUSEIPDB.lower(): AbuseIPDBProvider(cache_ttl_seconds=cache_ttl_seconds),
            PROVIDER_VIRUSTOTAL.lower(): VirusTotalProvider(cache_ttl_seconds=cache_ttl_seconds),
        }

        # Choose default provider
        if default_provider:
            self._default_provider = default_provider
            self._providers[default_provider.name.lower()] = default_provider
        elif offline_mode:
            self._default_provider = self._providers[PROVIDER_MOCK.lower()]
        else:
            # If real API keys exist in env, use AbuseIPDB by default; else fallback to Mock
            has_abuse = bool(os.environ.get(ABUSEIPDB_API_KEY_ENV, "").strip())
            has_vt = bool(os.environ.get(VIRUSTOTAL_API_KEY_ENV, "").strip())
            if has_abuse:
                self._default_provider = self._providers[PROVIDER_ABUSEIPDB.lower()]
            elif has_vt:
                self._default_provider = self._providers[PROVIDER_VIRUSTOTAL.lower()]
            else:
                self._default_provider = self._providers[PROVIDER_MOCK.lower()]

    @property
    def default_provider_name(self) -> str:
        return self._default_provider.name

    def get_provider(self, name: Optional[str] = None) -> BaseIntelProvider:
        """Resolve a provider by name or return default."""
        if not name:
            return self._default_provider
        clean = name.strip().lower()
        alias_map = {
            "mock": PROVIDER_MOCK.lower(),
            "mockprovider": PROVIDER_MOCK.lower(),
            "abuse": PROVIDER_ABUSEIPDB.lower(),
            "abuseipdb": PROVIDER_ABUSEIPDB.lower(),
            "vt": PROVIDER_VIRUSTOTAL.lower(),
            "virustotal": PROVIDER_VIRUSTOTAL.lower(),
        }
        resolved = alias_map.get(clean, clean)
        if resolved in self._providers:
            return self._providers[resolved]
        raise ValueError(f"Unknown threat intel provider '{name}'. Allowed: {list(self._providers.keys())}")

    # -----------------------------------------------------------------------
    # Indicator Extraction (Requirement 2)
    # -----------------------------------------------------------------------
    @staticmethod
    def extract_indicators(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract observable network indicators (IPs, ports, protocols, timestamps)
        from raw events, features dicts, or investigation reports.
        Strictly never invents missing indicators.
        """
        indicators: List[Dict[str, Any]] = []
        if not data:
            return indicators

        # Flatten context from multiple possible structures
        search_dicts: List[Dict[str, Any]] = [data]

        # If data is an investigation report
        if "supporting_evidence" in data and isinstance(data["supporting_evidence"], dict):
            supp = data["supporting_evidence"]
            if "network_facts" in supp and isinstance(supp["network_facts"], dict):
                search_dicts.append(supp["network_facts"])

        # If features / features_json exists
        if "features" in data and isinstance(data["features"], dict):
            search_dicts.append(data["features"])
        elif "features_json" in data and isinstance(data["features_json"], str):
            try:
                parsed = json.loads(data["features_json"])
                if isinstance(parsed, dict):
                    search_dicts.append(parsed)
            except Exception:
                pass

        if "network_context_json" in data:
            ctx = data["network_context_json"]
            if isinstance(ctx, dict):
                search_dicts.append(ctx)
            elif isinstance(ctx, str):
                try:
                    parsed = json.loads(ctx)
                    if isinstance(parsed, dict):
                        search_dicts.append(parsed)
                except Exception:
                    pass

        seen_keys = set()

        def add_indicator(ind_type: str, ind_val: str, role: str) -> None:
            dedup_key = (ind_type.lower(), str(ind_val).strip())
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                indicators.append({
                    "indicator_type": ind_type,
                    "indicator_value": str(ind_val).strip(),
                    "role": role,
                })

        # 1. Search for IP addresses
        ip_fields = [
            ("src_ip", "source_ip"),
            ("dst_ip", "destination_ip"),
            ("source_ip", "source_ip"),
            ("destination_ip", "destination_ip"),
            ("Src IP", "source_ip"),
            ("Dst IP", "destination_ip"),
            ("ip", "indicator_ip"),
            ("ip_address", "indicator_ip"),
        ]
        for d in search_dicts:
            for field_name, role in ip_fields:
                val = d.get(field_name)
                if val and isinstance(val, str) and IPV4_REGEX.match(val.strip()):
                    add_indicator("ip", val.strip(), role)

        # 2. Search for Ports
        port_fields = [
            ("Dst Port", "destination_port"),
            ("dst_port", "destination_port"),
            ("Src Port", "source_port"),
            ("src_port", "source_port"),
            ("port", "target_port"),
        ]
        for d in search_dicts:
            for field_name, role in port_fields:
                val = d.get(field_name)
                if val is not None:
                    try:
                        port_int = int(float(val))
                        if 0 < port_int <= 65535:
                            add_indicator("port", str(port_int), role)
                    except (ValueError, TypeError):
                        pass

        # 3. Search for Protocol
        for d in search_dicts:
            proto_val = d.get("Protocol") or d.get("protocol")
            if proto_val is not None:
                try:
                    proto_int = int(float(proto_val))
                    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
                    proto_name = proto_map.get(proto_int, f"Protocol-{proto_int}")
                    add_indicator("protocol", proto_name, "transport_protocol")
                except (ValueError, TypeError):
                    pass

        return indicators

    # -----------------------------------------------------------------------
    # Lookup and Cache Operations (Requirements 5 & 9)
    # -----------------------------------------------------------------------
    def lookup(
        self,
        indicator_type: str,
        indicator_value: str,
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Lookup threat intelligence for an indicator.
        Checks SQLite cache first. Only queries provider if cache missed,
        expired, or force_refresh is True.
        """
        clean_type = indicator_type.strip().lower()
        clean_val = str(indicator_value).strip()
        provider = self.get_provider(provider_name)

        # 1. Check Cache
        if not force_refresh:
            try:
                with ThreatIntelQueryStore(db_path=self._db_path) as q_store:
                    cached = q_store.get_cached_intel(
                        indicator_type=clean_type,
                        indicator_value=clean_val,
                        provider=provider.name,
                        valid_only=True,
                    )
                    if cached:
                        cached["cache_hit"] = True
                        logger.debug("Threat intel cache HIT: %s:%s (%s)", clean_type, clean_val, provider.name)
                        return cached
            except Exception as exc:
                logger.warning("Could not read threat intel cache: %s", exc)

        # 2. Query Provider on Cache Miss / Expiry / Force Refresh
        logger.info("Threat intel lookup: %s:%s provider=%s (force=%s)", clean_type, clean_val, provider.name, force_refresh)
        result = provider.lookup(clean_type, clean_val)
        result["cache_hit"] = False

        # 3. Cache into SQLite
        try:
            with AlertStore(db_path=self._db_path) as a_store:
                a_store.save_intel_cache(result)
                logger.debug("Threat intel cached: %s:%s (%s)", clean_type, clean_val, provider.name)
        except Exception as exc:
            logger.warning("Could not persist threat intel to cache: %s", exc)

        # 4. Append to JSON log file
        if self._log_to_file:
            self._log_intel_entry(result)

        return result

    def _log_intel_entry(self, entry: Dict[str, Any]) -> None:
        """Append lookup result to local JSON log."""
        try:
            THREAT_INTEL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(THREAT_INTEL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.error("Failed to append to threat intel log: %s", exc)

    # -----------------------------------------------------------------------
    # Enrichment Operations (Requirements 6, 7, 8)
    # -----------------------------------------------------------------------
    def enrich_indicators(
        self,
        indicators: List[Dict[str, Any]],
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> List[Dict[str, Any]]:
        """Perform lookups for a collection of extracted indicators."""
        results = []
        for ind in indicators:
            res = self.lookup(
                indicator_type=ind["indicator_type"],
                indicator_value=ind["indicator_value"],
                provider_name=provider_name,
                force_refresh=force_refresh,
            )
            # Include extraction role
            enriched_entry = dict(res)
            enriched_entry["role"] = ind.get("role", "indicator")
            results.append(enriched_entry)
        return results

    @staticmethod
    def compute_aggregate_verdict(lookups: List[Dict[str, Any]]) -> str:
        """
        Determine the overall threat intelligence verdict from multiple lookups.
        Precedence: MALICIOUS > SUSPICIOUS > NO_KNOWN_REPORTS > UNKNOWN/UNAVAILABLE
        """
        if not lookups:
            return VERDICT_UNKNOWN

        verdicts = [item.get("verdict", VERDICT_UNKNOWN) for item in lookups]
        if VERDICT_MALICIOUS in verdicts:
            return VERDICT_MALICIOUS
        if VERDICT_SUSPICIOUS in verdicts:
            return VERDICT_SUSPICIOUS
        if VERDICT_NO_KNOWN_REPORTS in verdicts:
            return VERDICT_NO_KNOWN_REPORTS
        return VERDICT_UNKNOWN

    def enrich_event(
        self,
        event: Dict[str, Any],
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Enrich a network-flow event without mutating the original event.
        """
        event_copy = copy.deepcopy(event)
        indicators = self.extract_indicators(event_copy)
        lookups = self.enrich_indicators(indicators, provider_name=provider_name, force_refresh=force_refresh)
        agg_verdict = self.compute_aggregate_verdict(lookups)

        limitations = []
        has_ip = any(ind["indicator_type"] == "ip" for ind in indicators)
        if not has_ip:
            limitations.append(
                "Source/Destination IP addresses were not present in the flow feature vector. "
                "No IP addresses were fabricated. Lookups were performed on observable port/protocol features."
            )

        if agg_verdict == VERDICT_NO_KNOWN_REPORTS:
            limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

        any_mock = any(item.get("is_mock") for item in lookups)
        if any_mock:
            limitations.append(MOCK_DATA_DISCLAIMER)

        enrichment_result = {
            "event_id": event_copy.get("event_id"),
            "indicators_extracted": indicators,
            "threat_intel_lookups": lookups,
            "aggregate_verdict": agg_verdict,
            "provider_used": provider_name or self.default_provider_name,
            "enriched_at": datetime.datetime.now().isoformat(),
            "limitations": limitations,
        }
        return enrichment_result

    def enrich_investigation(
        self,
        investigation_report: Dict[str, Any],
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """
        Enrich an existing investigation report with threat intelligence findings.
        Strictly preserves original predictions, assessments, and evidence.
        Appends findings into findings_by_agent['threat_intelligence'],
        adds a dedicated threat_intelligence section, and updates the database.
        """
        report = copy.deepcopy(investigation_report)
        indicators = self.extract_indicators(report)
        lookups = self.enrich_indicators(indicators, provider_name=provider_name, force_refresh=force_refresh)
        agg_verdict = self.compute_aggregate_verdict(lookups)

        # Synthesize clear, provider-attributed findings
        intel_findings_text: List[str] = []
        evidence_links: List[str] = []
        intel_limitations: List[str] = []
        any_mock = False

        if not indicators:
            intel_findings_text.append(
                "No observable indicators (IPs, Ports) were available in investigation telemetry for external enrichment."
            )
            intel_limitations.append("Telemetry lacked extractable indicators. No indicators were invented.")
        else:
            has_ip = any(ind["indicator_type"] == "ip" for ind in indicators)
            if not has_ip:
                intel_limitations.append(
                    "Source/Destination IP addresses were absent from flow features. "
                    "No IP was fabricated. Evaluated observable port/protocol indicators only."
                )

            for item in lookups:
                ind_type = item.get("indicator_type", "").upper()
                ind_val = item.get("indicator_value")
                provider = item.get("provider", "UnknownProvider")
                verdict = item.get("verdict", VERDICT_UNKNOWN)
                score = item.get("reputation_score")
                links = item.get("evidence_links", [])
                evidence_links.extend(links)
                is_mock = item.get("is_mock", False)
                if is_mock:
                    any_mock = True

                score_str = f" [Score/Confidence: {score}]" if score is not None else ""
                mock_tag = " [MOCK DEMO]" if is_mock else ""

                if verdict == VERDICT_MALICIOUS:
                    intel_findings_text.append(
                        f"HIGH THREAT INTEL: {ind_type} '{ind_val}' confirmed {verdict} by {provider}{score_str}{mock_tag}. "
                        "Prior malicious activity or abuse reported."
                    )
                elif verdict == VERDICT_SUSPICIOUS:
                    intel_findings_text.append(
                        f"ELEVATED RISK: {ind_type} '{ind_val}' flagged {verdict} by {provider}{score_str}{mock_tag}."
                    )
                elif verdict == VERDICT_NO_KNOWN_REPORTS:
                    intel_findings_text.append(
                        f"INTEL CLEAR: {ind_type} '{ind_val}' returned {verdict} from {provider}{mock_tag}."
                    )
                else:
                    intel_findings_text.append(
                        f"INTEL INCONCLUSIVE: {ind_type} '{ind_val}' returned {verdict} from {provider}{mock_tag}."
                    )

                for lim in item.get("limitations", []):
                    if lim not in intel_limitations:
                        intel_limitations.append(lim)

        if agg_verdict == VERDICT_NO_KNOWN_REPORTS:
            if NO_KNOWN_REPORTS_DISCLAIMER not in intel_limitations:
                intel_limitations.append(NO_KNOWN_REPORTS_DISCLAIMER)

        if any_mock and MOCK_DATA_DISCLAIMER not in intel_limitations:
            intel_limitations.append(MOCK_DATA_DISCLAIMER)

        # 1. Update findings_by_agent
        if "findings_by_agent" not in report:
            report["findings_by_agent"] = {}
        report["findings_by_agent"]["threat_intelligence"] = intel_findings_text

        # 2. Add dedicated threat_intelligence block
        report["threat_intelligence"] = {
            "status": "ENRICHED",
            "aggregate_verdict": agg_verdict,
            "provider_used": provider_name or self.default_provider_name,
            "indicators_analyzed": indicators,
            "lookups": lookups,
            "evidence_links": list(dict.fromkeys(evidence_links)),
            "last_checked": datetime.datetime.now().isoformat(),
            "limitations": intel_limitations,
            "is_mock": any_mock,
        }

        # 3. Append to limitations without overwriting existing
        existing_limitations = report.get("limitations", [])
        for lim in intel_limitations:
            if lim not in existing_limitations:
                existing_limitations.append(lim)
        report["limitations"] = existing_limitations

        # 4. Append recommended next steps if malicious/suspicious
        recs = report.get("recommended_next_steps", [])
        if agg_verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
            intel_rec = f"Escalate investigation: Correlate indicator external findings ({agg_verdict}) with host endpoint logs."
            if intel_rec not in recs:
                recs.append(intel_rec)
        report["recommended_next_steps"] = recs

        # 5. Persist updated report to DB if requested
        if persist:
            try:
                with AlertStore(db_path=self._db_path) as a_store:
                    # Update database row
                    cur = a_store._conn.execute(
                        """
                        UPDATE threat_investigations
                        SET findings_by_agent_json = ?,
                            limitations_json = ?,
                            recommended_next_steps_json = ?
                        WHERE investigation_id = ?;
                        """,
                        (
                            json.dumps(report["findings_by_agent"], ensure_ascii=False),
                            json.dumps(report["limitations"], ensure_ascii=False),
                            json.dumps(report["recommended_next_steps"], ensure_ascii=False),
                            report["investigation_id"],
                        ),
                    )
                    a_store._conn.commit()
                    logger.debug("Threat investigation %s updated with intel enrichment.", report["investigation_id"])
            except Exception as exc:
                logger.warning("Could not persist enriched investigation to DB: %s", exc)

        return report
