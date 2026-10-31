# Google Gemini Flash LLM Reasoning Agent (Stage 14) Technical Specification

> **Project:** Multi-Agent AI Security Operations Center (SOC) for Real-Time Threat Detection  
> **Repository Path:** `E:\multi-agent-soc`  
> **Component:** Stage 14 — Autonomous LLM Incident Reasoning & Policy-Validated Response Synthesis  
> **Status:** Production-Ready, Mock-Verified, Tested (87 Passing Tests)

---

## 1. Architecture & End-to-End Incident Workflow

The SOC processes network telemetry through a sequential, in-process, synchronous multi-agent pipeline (`kafka/consumer.py`). The Google Gemini Flash Reasoning Agent operates strictly **between** multi-agent correlation/investigation and the policy-validated response playbook engine:

```
[ Ingest Flow (REST/CSV) ]
            |
            v
 [ 1. Schema Validation & 78-Feature Alignment ]
            |
            v
 [ 2. Supervised Random Forest Classifier ]
            |
            v
 [ 3. Unsupervised Isolation Forest Anomaly Detector ]
            |
            v
 [ 4. SQLite Event & Detection Alert Persistence ]
            |
            v
 [ 5. Multi-Flow Alert Correlation Engine ]
            |
            v
 [ 6. Unified Threat Assessment (Score: 0.0 - 1.0, Priority: LOW/MED/HIGH/CRIT) ]
            |
            v
 [ 7. Autonomous Threat Investigation (Root Cause, Blast Radius, MITRE ATT&CK) ]
            |
            v
 [ 8. Threat Intelligence Enrichment (RFC 1918 Private IP Isolation Guard) ]
            |
            v (Incident Context Triggered)
 +-------------------------------------------------------------------------------+
 | 9. STAGE 14: GOOGLE GEMINI FLASH REASONING AGENT (agents/llm_reasoning/)     |
 |    - Compact Incident Summary & Telemetry Sanitization                        |
 |    - Strict Pydantic Schema: IncidentReasoningOutput                          |
 |    - MITRE ATT&CK Mapping & Evidence-Based Synthesis                          |
 |    - Uncertainty & Additional Evidence Documentation                          |
 |    - Graceful Fallback: Deterministic Synthesis if Offline/Rate-Limited       |
 +-------------------------------------------------------------------------------+
            |
            v (Structured LLM Recommendations)
 +-------------------------------------------------------------------------------+
 | 10. STAGE 12: RESPONSE PLAYBOOK ENGINE (agents/response_playbooks/engine.py)  |
 |    - Allowlist Enforcement: Reject Unknown / Unsupported LLM Actions         |
 |    - Policy Severity Gate: High/Critical Attacks Escalated                   |
 |    - Safety Enforcement: Dry-Run Mode Always Active (dry_run=True)           |
 |    - Human-in-the-Loop: Disruptive Actions Require Manual Approval           |
 +-------------------------------------------------------------------------------+
            |
            v
 [ 11. SQLite Persistence (llm_reasoning, response_playbooks) ]
            |
            v
 [ 12. REST Dashboard API & React Frontend UI (App.jsx) ]
```

---

## 2. Model Identifier & Official SDK Configuration

### SDK
- Uses Google's official, modern Python SDK: **`google-genai`** (version 2.14.0+).
- Structured outputs are enforced via `types.GenerateContentConfig(response_mime_type="application/json", response_schema=IncidentReasoningOutput)`.

### Model Identifier
- **Default Identifier:** `gemini-2.5-flash`
- **Fallback / Alternative:** `gemini-2.0-flash` or `gemini-1.5-flash`
- Configurable via environment variable `GEMINI_MODEL`.

### Environment Variables
Configure the following in your `.env` file (see `.env.example`):

```bash
# Official Google GenAI API Key (from https://aistudio.google.com/)
GEMINI_API_KEY=your_actual_api_key_here

# Model Identifier
GEMINI_MODEL=gemini-2.5-flash

# Enable / Disable Toggle (true / false)
GEMINI_REASONING_ENABLED=true

# Request Timeout (seconds)
GEMINI_TIMEOUT_SECONDS=12.0

# Max Retries for Transient Errors
GEMINI_MAX_RETRIES=2
```

---

## 3. Disabling LLM & Deterministic Fallback Mode

If no `GEMINI_API_KEY` is provided, or if `GEMINI_REASONING_ENABLED=false`:
- The system automatically activates `MockReasoningProvider`.
- It generates deterministic, rule-based reasoning reports using existing Random Forest predictions, anomaly scores, and investigation findings.
- The pipeline never crashes or halts event ingestion due to missing API keys or external network issues.
- All mock reports are transparently labeled with `[OFFLINE DEMO / MOCK REASONING - NO EXTERNAL API CALL]`.

---

## 4. Structured Output Schema (`IncidentReasoningOutput`)

The agent validates all LLM output using Pydantic:

| Field | Type | Description |
| :--- | :--- | :--- |
| `incident_id` | `str` | UUID or identifier of the incident cluster. |
| `summary` | `str` | Concise executive summary of observed threat telemetry. |
| `likely_attack` | `str` | Probable attack classification (e.g., `Infiltration`, `DDoS-SYN`, `Brute-Force`). |
| `evidence` | `List[str]` | Concrete observational facts from model outputs and network metrics. |
| `mitre_techniques`| `List[str]` | Associated MITRE ATT&CK technique IDs (e.g., `T1046`, `T1190`). |
| `confidence` | `float` | Model confidence score ($0.0 \le c \le 1.0$), clamped and validated. |
| `uncertainties` | `List[str]` | Known telemetry gaps, ambiguous signals, or unconfirmed hypotheses. |
| `recommended_actions` | `List[RecommendedActionItem]` | Policy-compatible actions recommended to the response engine. |
| `additional_evidence_needed` | `List[str]` | Secondary telemetry sources (e.g., host auditd logs, auth logs) needed for confirmation. |

### Each `RecommendedActionItem`:
- `action_name`: Allowlisted action token (e.g., `RECOMMEND_CONTAINMENT`, `FLAG_FOR_ANALYST_REVIEW`, `INCREASE_MONITORING`).
- `reason`: Technical rationale supporting the action.
- `priority`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `supporting_evidence`: List of telemetry points supporting this specific recommendation.
- `requires_approval`: Boolean indicating if human analyst authorization is mandatory.

---

## 5. Security & Safety Safeguards

1. **Advisory Authority Only:**
   - The LLM **never** directly executes shell commands, edits firewall rules, modifies IP tables, or disconnects virtual machines.
   - All containment actions require approval from a human security analyst.
2. **Allowlist Enforcement:**
   - The Response Playbook Engine (`agents/response_playbooks/engine.py`) enforces strict action allowlisting:
     - `RECOMMEND_CONTAINMENT`
     - `FLAG_FOR_ANALYST_REVIEW`
     - `INCREASE_MONITORING`
     - `GATHER_ADDITIONAL_EVIDENCE`
     - `LOG_BASELINE_ACTIVITY`
   - Any hallucinated or unauthorized actions are immediately rejected with an `LLM_ACTION_REJECTED` audit record.
3. **Prompt Injection Hardening:**
   - Security telemetry is bounded to 6,000 characters and isolated within XML-style `<security_telemetry>` delimiting tags.
   - Raw payload and header strings are sanitized to disarm directive overrides (e.g., `"ignore previous instructions"`).
4. **RFC 1918 Private IP Isolation:**
   - Lab subnets (`192.168.56.0/24`, `10.0.0.0/8`, `172.16.0.0/12`, `127.0.0.0/8`) are never sent to external intelligence lookups.
5. **Dry-Run Enforcement:**
   - All response playbooks execute with `dry_run=True` by default.

---

## 6. REST API Endpoints

### LLM Reasoning:
- `GET /api/reasoning`: Retrieve recent LLM incident reasoning reports (supports `limit` and `status` query parameters).
- `GET /api/reasoning/{target_id}`: Look up reasoning by report ID, incident ID, or event ID.
- `GET /api/agents/status`: Reports health and provider status of all agents, including Gemini Flash.

### Playbook Approval & Containment:
- `GET /api/playbooks`: List generated response playbooks with approval statuses.
- `POST /api/playbooks/{playbook_id}/approve`: Analyst approval endpoint for pending actions (accepts `analyst_id` and `action="APPROVE"` or `"REJECT"`).

---

## 7. Testing Instructions

### Run Fast Offline Regression Suite (No API Key Required):
```bash
pytest test_llm_reasoning.py -v
```

### Run Full Repository Test Suite (87 tests passing):
```bash
pytest -v
```

### Run Optional Live Gemini Integration Test:
```bash
# Set your real API key in the shell or .env
set GEMINI_API_KEY=your_gemini_api_key
set RUN_LIVE_GEMINI_TEST=true
pytest test_llm_reasoning.py -k test_live_gemini_api_integration -v
```

### Run Multi-Agent Benchmark & Evaluation Suite:
```bash
python scripts/evaluate_soc.py --mode all --sample 100 --events 20
```

---

## 8. React Dashboard (Frontend) Integration

The React dashboard (`frontend/src/App.jsx`) includes:
1. **Playbooks & Gemini AI Tab:** Dedicated view displaying incident triage cards, LLM reasoning summaries, MITRE technique tags, uncertainty indicators, and recommended actions.
2. **Interactive Analyst Approval UI:**
   - Action buttons: `APPROVE (DRY-RUN)` and `REJECT`.
   - Explicit confirmation modal dialogs to prevent accidental clicks.
   - Real-time status banners reflecting `PENDING_APPROVAL`, `APPROVED`, or `REJECTED`.
   - Double-click debounce protection (`approvingId` loading state).
3. **Event Inspection Drawer:** Deep-dive inspection showing full correlated LLM reasoning reports for selected events.
