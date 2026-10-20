"""
query_intel.py
==============
Command-line interface for Threat Intelligence Enrichment (Stage 11).

Multi-Agent SOC Project -- Stage 11

CAPABILITIES:
  - Indicator Lookups: Query IP or port against configured provider (Mock, AbuseIPDB, VirusTotal).
  - Caching & Expiry: Reads active cached results; skips repeated requests unless --force is specified.
  - Enrichment:
      --enrich-event <EVENT_ID>: Extract indicators from stored event and enrich.
      --enrich-investigation <INV_ID>: Enrich stored investigation report and persist findings.
  - Cache Management:
      --cached / --recent: View cached threat intelligence entries.
      --verdict <VERDICT>: Filter cached entries by verdict.
      --summary: Summary statistics of cache lookups.
"""

import argparse
import json
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_intelligence.agent import ThreatIntelligenceAgent
from agents.threat_intelligence.config import (
    MOCK_DATA_DISCLAIMER,
    NO_KNOWN_REPORTS_DISCLAIMER,
    PROVIDER_ABUSEIPDB,
    PROVIDER_MOCK,
    PROVIDER_VIRUSTOTAL,
    VERDICT_MALICIOUS,
    VERDICT_NO_KNOWN_REPORTS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
)
from agents.threat_intelligence.providers import IPV4_REGEX
from storage.config import DB_PATH
from storage.query import AlertQueryStore, ThreatIntelQueryStore, ThreatInvestigationQueryStore

# ---------------------------------------------------------------------------
# ANSI Colour Formatting
# ---------------------------------------------------------------------------
ANSI = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
GREEN = "\033[92m" if ANSI else ""
RED = "\033[91m" if ANSI else ""
YELLOW = "\033[93m" if ANSI else ""
CYAN = "\033[96m" if ANSI else ""
BOLD = "\033[1m" if ANSI else ""
DIM = "\033[2m" if ANSI else ""
RESET = "\033[0m" if ANSI else ""

DIV = "=" * 78
DIV2 = "-" * 78


def format_verdict(verdict: str) -> str:
    if verdict == VERDICT_MALICIOUS:
        return f"{RED}{BOLD}{verdict}{RESET}"
    elif verdict == VERDICT_SUSPICIOUS:
        return f"{YELLOW}{BOLD}{verdict}{RESET}"
    elif verdict == VERDICT_NO_KNOWN_REPORTS:
        return f"{GREEN}{verdict}{RESET}"
    return f"{CYAN}{verdict}{RESET}"


def print_intel_card(item: dict) -> None:
    ind_type = item.get("indicator_type", "N/A").upper()
    ind_val = item.get("indicator_value", "N/A")
    provider = item.get("provider", "N/A")
    verdict = item.get("verdict", VERDICT_UNKNOWN)
    score = item.get("reputation_score")
    is_mock = item.get("is_mock", False)
    cache_hit = item.get("cache_hit")
    last_checked = item.get("last_checked", "N/A")
    expires_at = item.get("expires_at", "N/A")
    is_expired = item.get("is_expired", False)

    print(DIV2)
    hit_str = f" [{CYAN}CACHE HIT{RESET}]" if cache_hit else " [LIVE/FRESH]"
    mock_str = f" {YELLOW}[MOCK FIXTURE]{RESET}" if is_mock else f" {GREEN}[REAL INTEL]{RESET}"
    print(f"  {BOLD}{ind_type}:{RESET} {BOLD}{ind_val}{RESET}  |  Provider: {provider}{mock_str}{hit_str}")
    print(f"  Verdict: {format_verdict(verdict)}", end="")
    if score is not None:
        print(f"  |  Score/Confidence: {score:.1f}", end="")
    print()
    print(f"  Last Checked: {last_checked}  |  Expires: {expires_at}{' (EXPIRED)' if is_expired else ''}")

    links = item.get("evidence_links", [])
    if links:
        print(f"  Evidence Links: {', '.join(links)}")

    raw = item.get("raw_response", {})
    if raw:
        if isinstance(raw, dict):
            # Print select highlights
            details = []
            for k in ("abuseConfidenceScore", "totalReports", "countryCode", "isp", "last_analysis_stats", "note"):
                if k in raw:
                    details.append(f"{k}={raw[k]}")
            if details:
                print(f"  Raw Highlights: {', '.join(details)}")

    limitations = item.get("limitations", [])
    if limitations:
        print("  Limitations / Disclaimers:")
        for lim in limitations:
            print(f"    - {DIM}{lim}{RESET}")


def cmd_lookup(args: argparse.Namespace, agent: ThreatIntelligenceAgent) -> None:
    ind_val = args.lookup.strip()
    ind_type = args.type.strip().lower() if args.type else None

    # Auto-detect if not provided
    if not ind_type:
        if IPV4_REGEX.match(ind_val):
            ind_type = "ip"
        elif ind_val.isdigit():
            ind_type = "port"
        else:
            ind_type = "ip"

    print(f"\n{DIV}")
    print(f"  THREAT INTELLIGENCE LOOKUP: {ind_type.upper()} '{ind_val}'")
    print(f"  Provider: {args.provider or agent.default_provider_name}  |  Force Refresh: {args.force}")
    print(DIV)

    result = agent.lookup(
        indicator_type=ind_type,
        indicator_value=ind_val,
        provider_name=args.provider,
        force_refresh=args.force,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print_intel_card(result)
    print(DIV)


def cmd_enrich_event(args: argparse.Namespace, agent: ThreatIntelligenceAgent) -> None:
    event_id = args.enrich_event.strip()
    with AlertQueryStore() as q:
        event = q.get_event_by_id(event_id)

    if not event:
        print(f"{RED}Error: Event ID '{event_id}' not found in database.{RESET}")
        return

    print(f"\n{DIV}")
    print(f"  ENRICHING EVENT: {event_id}")
    print(f"  Source: {event.get('source')}  |  Label: {event.get('actual_label')}")
    print(DIV)

    enriched = agent.enrich_event(event, provider_name=args.provider, force_refresh=args.force)

    if args.json:
        print(json.dumps(enriched, indent=2))
        return

    print(f"  Indicators Extracted: {len(enriched['indicators_extracted'])}")
    for ind in enriched["indicators_extracted"]:
        print(f"    - {ind['indicator_type'].upper()}: {ind['indicator_value']} (role: {ind['role']})")

    print(f"\n  Overall Threat Intel Verdict: {format_verdict(enriched['aggregate_verdict'])}")
    print(f"\n  Detailed Lookups:")
    for lk in enriched["threat_intel_lookups"]:
        print_intel_card(lk)

    if enriched["limitations"]:
        print("\n  Enrichment Limitations:")
        for lim in enriched["limitations"]:
            print(f"    - {DIM}{lim}{RESET}")
    print(DIV)


def cmd_enrich_investigation(args: argparse.Namespace, agent: ThreatIntelligenceAgent) -> None:
    inv_id = args.enrich_investigation.strip()
    with ThreatInvestigationQueryStore() as q:
        inv = q.get_investigation_by_id(inv_id)
        if not inv:
            # Check by event_id
            inv = q.get_investigation_by_event_id(inv_id)

    if not inv:
        print(f"{RED}Error: Threat Investigation '{inv_id}' not found in database.{RESET}")
        return

    print(f"\n{DIV}")
    print(f"  ENRICHING THREAT INVESTIGATION: {inv.get('investigation_id')}")
    print(f"  Event ID: {inv.get('event_id')}  |  Category: {inv.get('threat_category')}")
    print(DIV)

    enriched = agent.enrich_investigation(inv, provider_name=args.provider, force_refresh=args.force, persist=True)

    if args.json:
        print(json.dumps(enriched, indent=2))
        return

    intel_block = enriched.get("threat_intelligence", {})
    print(f"  Threat Intel Status : {intel_block.get('status')}")
    print(f"  Aggregate Verdict   : {format_verdict(intel_block.get('aggregate_verdict', 'UNKNOWN'))}")
    print(f"  Provider Used       : {intel_block.get('provider_used')}")
    print(f"  Indicators Evaluated: {len(intel_block.get('indicators_analyzed', []))}")

    print("\n  Findings Added by Threat Intelligence Agent:")
    findings = enriched.get("findings_by_agent", {}).get("threat_intelligence", [])
    for f in findings:
        print(f"    * {f}")

    print("\n  Updated Recommended Next Steps:")
    for step in enriched.get("recommended_next_steps", []):
        print(f"    - {step}")

    if enriched.get("limitations"):
        print("\n  Investigation Limitations (Preserved & Enriched):")
        for lim in enriched.get("limitations", []):
            print(f"    - {DIM}{lim}{RESET}")

    print(f"\n{GREEN}[OK] Investigation {inv.get('investigation_id')} enriched and updated in database.{RESET}")
    print(DIV)


def cmd_cached(args: argparse.Namespace) -> None:
    limit = args.limit or 20
    with ThreatIntelQueryStore() as q:
        if args.verdict:
            records = q.get_intel_by_verdict(args.verdict.strip())
        elif args.provider:
            records = q.get_intel_by_provider(args.provider.strip())
        else:
            records = q.get_recent_intel(n=limit)

    if args.json:
        print(json.dumps(records, indent=2))
        return

    print(f"\n{DIV}")
    print(f"  CACHED THREAT INTELLIGENCE (Records: {len(records)})")
    if args.verdict:
        print(f"  Filter: verdict={args.verdict}")
    if args.provider:
        print(f"  Filter: provider={args.provider}")
    print(DIV)

    if not records:
        print("  No cached threat intelligence entries found.")
    else:
        for r in records:
            print_intel_card(r)
    print(DIV)


def cmd_summary(args: argparse.Namespace) -> None:
    with ThreatIntelQueryStore() as q:
        stats = q.summary_stats_intel()

    if args.json:
        print(json.dumps(stats, indent=2))
        return

    print(f"\n{DIV}")
    print(f"  THREAT INTELLIGENCE CACHE SUMMARY")
    print(DIV)
    print(f"  Total Cached Lookups : {stats['total_cached']}")
    print(f"  Real External Lookups: {stats['real_count']}")
    print(f"  Mock / Demo Lookups  : {stats['mock_count']}")
    print(f"  Expired Entries      : {stats['expired_count']}")

    print("\n  Verdicts Breakdown:")
    for verd, cnt in stats["verdicts"].items():
        print(f"    {format_verdict(verd):<30} : {cnt}")

    print("\n  Providers Breakdown:")
    for prov, cnt in stats["providers"].items():
        print(f"    {prov:<20} : {cnt}")
    print(DIV)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query, inspect, and enrich Threat Intelligence (Stage 11)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--lookup", metavar="INDICATOR", help="Lookup an observable indicator (IP or Port)")
    group.add_argument("--enrich-event", metavar="EVENT_ID", help="Enrich a stored event by ID")
    group.add_argument("--enrich-investigation", metavar="INV_ID", help="Enrich a stored investigation report by ID")
    group.add_argument("--cached", action="store_true", help="View cached threat intelligence entries")
    group.add_argument("--summary", action="store_true", help="Display cache statistical summary")

    parser.add_argument("--type", choices=["ip", "port", "protocol"], help="Indicator type (default: auto-detect)")
    parser.add_argument("--provider", choices=["mock", "abuseipdb", "virustotal"], help="Target provider")
    parser.add_argument("--force", action="store_true", help="Force refresh, bypassing active SQLite cache")
    parser.add_argument("--verdict", help="Filter cached entries by verdict (MALICIOUS, SUSPICIOUS, etc.)")
    parser.add_argument("--limit", type=int, default=20, help="Max entries to return for --cached (default: 20)")
    parser.add_argument("--json", action="store_true", help="Output in machine-readable JSON format")
    parser.add_argument("--offline", action="store_true", help="Enforce offline mock mode")

    args = parser.parse_args()

    agent = ThreatIntelligenceAgent(offline_mode=args.offline)

    if args.lookup:
        cmd_lookup(args, agent)
    elif args.enrich_event:
        cmd_enrich_event(args, agent)
    elif args.enrich_investigation:
        cmd_enrich_investigation(args, agent)
    elif args.cached:
        cmd_cached(args)
    elif args.summary:
        cmd_summary(args)


if __name__ == "__main__":
    main()
