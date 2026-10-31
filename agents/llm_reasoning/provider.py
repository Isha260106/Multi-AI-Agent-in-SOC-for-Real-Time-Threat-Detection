"""
agents/llm_reasoning/provider.py
================================
Modular Provider Interfaces for LLM Reasoning.

Provides:
  - BaseReasoningProvider: Abstract interface
  - GeminiFlashProvider: Official google-genai SDK wrapper for Gemini Flash
  - MockReasoningProvider: Offline deterministic mock for CI and local evaluation
"""

import abc
import concurrent.futures
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple, Type

from agents.llm_reasoning.config import (
    AGENT_NAME,
    AGENT_VERSION,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    FALLBACK_GEMINI_MODEL,
    GEMINI_API_KEY_ENV,
    GEMINI_MODEL_ENV,
    MAX_RETRIES,
    MOCK_REASONING_DISCLAIMER,
    REASONING_RUNTIME_LOG,
    STATUS_ERROR,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
)
from agents.llm_reasoning.schemas import IncidentReasoningOutput, RecommendedActionItem

logger = logging.getLogger("SOC.LLMReasoning.Provider")
if not logger.handlers:
    REASONING_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(REASONING_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


class BaseReasoningProvider(abc.ABC):
    """Abstract interface for LLM reasoning providers."""

    def __init__(self, model_name: str, is_mock: bool = False):
        self.model_name = model_name
        self.is_mock = is_mock

    @abc.abstractmethod
    def generate_reasoning(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Tuple[Optional[IncidentReasoningOutput], Optional[str], str]:
        """
        Generate structured reasoning from prompt.

        Returns:
            (IncidentReasoningOutput or None, error_message or None, status_code)
        """
        raise NotImplementedError


class GeminiFlashProvider(BaseReasoningProvider):
    """
    Google Gemini Flash provider using the official `google-genai` SDK.
    Enforces structured output parsing, explicit timeout guards, and rate-limit handling.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._api_key = api_key or os.getenv(GEMINI_API_KEY_ENV, "")
        configured_model = model_name or os.getenv(GEMINI_MODEL_ENV, DEFAULT_GEMINI_MODEL)
        super().__init__(model_name=configured_model, is_mock=False)
        self.timeout_seconds = timeout_seconds
        self._client = None

        if self._api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=self._api_key)
                logger.info("Initialized Google GenAI client for model: %s", self.model_name)
            except Exception as exc:
                logger.error("Failed to initialize Google GenAI client: %s", exc)
                self._client = None
        else:
            logger.warning(
                "GeminiFlashProvider initialized without %s. Provider will report UNAVAILABLE.",
                GEMINI_API_KEY_ENV,
            )

    @property
    def is_available(self) -> bool:
        return bool(self._client and self._api_key)

    def generate_reasoning(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Tuple[Optional[IncidentReasoningOutput], Optional[str], str]:
        """
        Call Gemini Flash with strict structured output constraint and timeout guard.
        """
        if not self.is_available:
            return (
                None,
                f"{GEMINI_API_KEY_ENV} is not configured or Google GenAI client failed to initialize.",
                STATUS_UNAVAILABLE,
            )

        from google.genai import types

        thinking_config = None
        thinking_level = os.getenv("GEMINI_THINKING_LEVEL", "MEDIUM").upper()
        if hasattr(types, "ThinkingConfig") and hasattr(types, "ThinkingLevel"):
            try:
                level_enum = getattr(types.ThinkingLevel, thinking_level, types.ThinkingLevel.MEDIUM)
                thinking_config = types.ThinkingConfig(thinking_level=level_enum)
            except Exception:
                thinking_config = None

        config_kwargs = {
            "response_mime_type": "application/json",
            "response_schema": IncidentReasoningOutput,
            "temperature": 0.1,
            "max_output_tokens": 2048,
        }
        if thinking_config is not None:
            config_kwargs["thinking_config"] = thinking_config

        config = types.GenerateContentConfig(**config_kwargs)

        effective_timeout = timeout or self.timeout_seconds

        def _call_api(model_to_use: str):
            return self._client.models.generate_content(
                model=model_to_use,
                contents=prompt,
                config=config,
            )

        last_error = None
        for attempt in range(1, MAX_RETRIES + 1):
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = executor.submit(_call_api, self.model_name)
            try:
                response = future.result(timeout=effective_timeout)
                executor.shutdown(wait=False)

                if not response or not response.text:
                    return None, "Empty response received from Gemini Flash API.", STATUS_ERROR

                raw_json = response.text
                parsed_data = json.loads(raw_json)
                output = IncidentReasoningOutput.model_validate(parsed_data)
                return output, None, "SUCCESS"

            except concurrent.futures.TimeoutError:
                executor.shutdown(wait=False)
                last_error = f"Gemini API request timed out after {effective_timeout:.1f}s."
                logger.warning("Attempt %d/%d timed out: %s", attempt, MAX_RETRIES, last_error)
            except json.JSONDecodeError as jde:
                executor.shutdown(wait=False)
                last_error = f"Malformed JSON from Gemini model: {jde}"
                logger.warning("Attempt %d/%d received malformed JSON: %s", attempt, MAX_RETRIES, jde)
            except Exception as exc:
                executor.shutdown(wait=False)
                err_str = str(exc)
                # Check for rate limiting / 429
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str.upper() or "QUOTA" in err_str.upper():
                    logger.warning("Gemini rate limit / quota exceeded: %s", err_str)
                    return None, f"Gemini rate limit exceeded: {err_str}", STATUS_RATE_LIMITED
                last_error = f"Gemini API invocation error: {err_str}"
                logger.warning("Attempt %d/%d failed: %s", attempt, MAX_RETRIES, err_str)

            time.sleep(0.5 * attempt)

        # Fallback to alternative model if primary failed and fallback is configured
        fallback_model = os.getenv("GEMINI_FALLBACK_MODEL", FALLBACK_GEMINI_MODEL)
        if fallback_model and fallback_model != self.model_name:
            try:
                logger.info("Primary model %s failed. Attempting fallback model: %s", self.model_name, fallback_model)
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(_call_api, fallback_model)
                response = future.result(timeout=effective_timeout)
                executor.shutdown(wait=False)
                if response and response.text:
                    parsed_data = json.loads(response.text)
                    output = IncidentReasoningOutput.model_validate(parsed_data)
                    return output, None, "SUCCESS"
            except Exception as fb_exc:
                logger.warning("Fallback model %s also failed: %s", fallback_model, fb_exc)

        return None, last_error or "Unknown failure during Gemini Flash generation.", STATUS_ERROR


class MockReasoningProvider(BaseReasoningProvider):
    """
    Deterministic offline mock provider.
    Synthesizes compliant IncidentReasoningOutput for unit testing and offline development
    without requiring API keys or incurring costs.
    """

    def __init__(self, model_name: str = "mock-gemini-2.5-flash"):
        super().__init__(model_name=model_name, is_mock=True)

    def generate_reasoning(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Tuple[Optional[IncidentReasoningOutput], Optional[str], str]:
        ctx = context or {}
        incident_id = ctx.get("incident_id") or "incident-mock-001"
        category = str(ctx.get("category", "Benign"))
        severity = str(ctx.get("severity", "LOW")).upper()
        src_ip = ctx.get("src_ip", "192.168.56.101")
        dst_port = ctx.get("dst_port", 80)
        conf = float(ctx.get("confidence", 0.85))

        is_critical = (
            "infilteration" in category.lower()
            or "infiltration" in category.lower()
            or severity in ("HIGH", "CRITICAL")
        )
        is_anomaly = "anomaly" in category.lower() or severity == "MEDIUM"

        ci = ctx.get("content_and_context_inspection")
        if ci and ci.get("verdict") == "GENUINE_USER_HIGH_VOLUME":
            output = IncidentReasoningOutput(
                incident_id=incident_id,
                summary="Data transfer volume evaluated by Content & Context Inspection and verified as genuine user/system activity (e.g., routine backup/development sync). False positive suppressed.",
                likely_attack="Genuine User / System High-Volume Operation",
                evidence=[
                    f"Content inspection verdict: GENUINE_USER_HIGH_VOLUME ({ci.get('volume_bytes', 0)} bytes).",
                    "Authorized process and trusted destination confirmed.",
                    "Zero sensitive credentials or post-compromise indicators detected.",
                ],
                mitre_techniques=[],
                confidence=0.92,
                uncertainties=[],
                recommended_actions=[
                    RecommendedActionItem(
                        action="ACTION_LOG_BASELINE",
                        target="Central Storage",
                        reason="Record verified genuine high-volume baseline transfer.",
                        priority="LOW",
                        supporting_evidence=["Legitimate user operation."],
                        requires_approval=False,
                    )
                ],
                additional_evidence_needed=[],
            )
            return output, None, "SUCCESS"

        seq = ctx.get("coordinated_attack_sequence")
        if seq and (seq.get("stages_detected") or seq.get("stage_count", 0) >= 2):
            stages = seq.get("stages_detected", [])
            techniques = seq.get("mitre_techniques", ["T1110", "T1548", "T1048"])
            output = IncidentReasoningOutput(
                incident_id=incident_id,
                summary=f"Coordinated Multi-Stage Attack confirmed across {len(stages)} kill-chain stages ({' -> '.join(stages)}). Immediate containment recommended.",
                likely_attack="Coordinated Multi-Stage Attack",
                evidence=[
                    f"Observed kill-chain sequence: {' -> '.join(stages)}.",
                    seq.get("correlation_reason", "Correlated multi-agent progression."),
                ],
                mitre_techniques=techniques,
                confidence=0.95,
                uncertainties=["Target endpoint internal damage assessment in progress."],
                recommended_actions=[
                    RecommendedActionItem(
                        action="ACTION_RECOMMEND_CONTAINMENT",
                        target=str(src_ip),
                        reason=f"Halt multi-stage attack progression ({' -> '.join(stages)}).",
                        priority="HIGH",
                        supporting_evidence=[f"Multi-stage correlation: {len(stages)} stages."],
                        requires_approval=True,
                    ),
                    RecommendedActionItem(
                        action="ACTION_FLAG_ANALYST_REVIEW",
                        target="SOC Tier-2 Queue",
                        reason="Verify host integrity across all compromised stages.",
                        priority="HIGH",
                        supporting_evidence=["Multi-stage progression confirmed."],
                        requires_approval=False,
                    ),
                ],
                additional_evidence_needed=["Endpoint forensic image."],
            )
            return output, None, "SUCCESS"

        if is_critical:
            output = IncidentReasoningOutput(
                incident_id=incident_id,
                summary=f"High-confidence network infiltration pattern detected against port {dst_port}. Flow telemetry indicates payload anomalies and anomalous packet duration consistent with unauthorized exploitation.",
                likely_attack="Network Infiltration / Remote Exploit",
                evidence=[
                    f"Supervised Random Forest classified flow as Infilteration with {conf:.1%} confidence.",
                    f"Target host destination port {dst_port} received burst connection volume.",
                    f"Isolation Forest flagged flow duration as anomalous outlier.",
                ],
                mitre_techniques=["T1190", "T1046", "T1071"],
                confidence=min(0.95, max(0.70, conf)),
                uncertainties=[
                    "Exact payload shellcode contents unavailable (metadata-only flow capture).",
                    "Target application crash or command execution status unverified on host endpoint.",
                ],
                recommended_actions=[
                    RecommendedActionItem(
                        action="ACTION_RECOMMEND_CONTAINMENT",
                        target=str(src_ip),
                        reason="Contain remote source host to halt active exploit sequencing.",
                        priority="HIGH",
                        supporting_evidence=[
                            "High-confidence Infiltration classification from Random Forest.",
                            f"Suspicious traffic targeting destination port {dst_port}.",
                        ],
                        requires_approval=True,
                    ),
                    RecommendedActionItem(
                        action="ACTION_FLAG_ANALYST_REVIEW",
                        target="SOC Tier-2 Queue",
                        reason="Human analyst verification required prior to destructive host containment.",
                        priority="HIGH",
                        supporting_evidence=["Automated policy mandates analyst review for disruptive actions."],
                        requires_approval=False,
                    ),
                    RecommendedActionItem(
                        action="ACTION_INCREASE_MONITORING",
                        target=f"Port {dst_port}",
                        reason="Tighten sampling window for victim host to detect potential lateral movement.",
                        priority="MEDIUM",
                        supporting_evidence=["Multi-flow clustering observed."],
                        requires_approval=False,
                    ),
                ],
                additional_evidence_needed=[
                    "Victim endpoint syslog and auth.log for process execution traces.",
                    "Full PCAP payload capture of flow session.",
                ],
            )
        elif is_anomaly:
            output = IncidentReasoningOutput(
                incident_id=incident_id,
                summary=f"Statistical anomaly observed in network flow metrics without verified supervised attack signature. Behavior deviates from historical baseline.",
                likely_attack="Suspicious Network Anomaly / Probe",
                evidence=[
                    "Isolation Forest anomaly score exceeded baseline threshold.",
                    f"Connection parameters on port {dst_port} exhibit atypical inter-arrival timing.",
                ],
                mitre_techniques=["T1046"],
                confidence=0.60,
                uncertainties=[
                    "Could represent benign maintenance script, backup job, or transient network congestion.",
                    "Supervised detection model did not classify flow as known exploit.",
                ],
                recommended_actions=[
                    RecommendedActionItem(
                        action="ACTION_INCREASE_MONITORING",
                        target=str(src_ip),
                        reason="Increase monitoring resolution to evaluate periodicity of source host.",
                        priority="MEDIUM",
                        supporting_evidence=["Statistical deviation flagged by Isolation Forest."],
                        requires_approval=False,
                    ),
                    RecommendedActionItem(
                        action="ACTION_GATHER_EVIDENCE",
                        target="60-Minute Flow History",
                        reason="Correlate with previous baseline connections from source host.",
                        priority="LOW",
                        supporting_evidence=["Differentiate periodic batch job from attacker probe."],
                        requires_approval=False,
                    ),
                ],
                additional_evidence_needed=[
                    "Service logs from destination service.",
                    "DNS query logs for source host.",
                ],
            )
        else:
            output = IncidentReasoningOutput(
                incident_id=incident_id,
                summary="Observed flow parameters conform to normal baseline distribution. No malicious indicators or anomalous deviations detected.",
                likely_attack="Benign Traffic",
                evidence=[
                    "Supervised Random Forest classified flow as Benign.",
                    "Anomaly detection score remains within 1-sigma normal distribution.",
                ],
                mitre_techniques=[],
                confidence=0.92,
                uncertainties=[
                    "Encrypted payload content cannot be inspected via flow statistics.",
                ],
                recommended_actions=[
                    RecommendedActionItem(
                        action="ACTION_LOG_BASELINE",
                        target="Central Storage",
                        reason="Record benign flow metrics to maintain rolling baseline statistics.",
                        priority="LOW",
                        supporting_evidence=["Flow metrics align with established benign profiles."],
                        requires_approval=False,
                    ),
                ],
                additional_evidence_needed=[],
            )

        return output, None, "SUCCESS"
