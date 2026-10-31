"""
agents/llm_reasoning/config.py
==============================
Configuration for Google Gemini Flash LLM Reasoning Agent.

Multi-Agent SOC Project -- Stage 14: LLM Incident Reasoning & Response Synthesis
"""

import os
import pathlib

# Project paths
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_DIR = PROJECT_ROOT / "logs"

# Environment Variable Names
GEMINI_API_KEY_ENV = "GEMINI_API_KEY"
GEMINI_MODEL_ENV = "GEMINI_MODEL"
GEMINI_FALLBACK_MODEL_ENV = "GEMINI_FALLBACK_MODEL"
GEMINI_THINKING_LEVEL_ENV = "GEMINI_THINKING_LEVEL"
GEMINI_ENABLED_ENV = "GEMINI_REASONING_ENABLED"

# Attempt loading from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except Exception:
    pass

# Model Identifiers
DEFAULT_GEMINI_MODEL = os.getenv(GEMINI_MODEL_ENV, "gemini-3.8-flash")
FALLBACK_GEMINI_MODEL = os.getenv(GEMINI_FALLBACK_MODEL_ENV, "gemini-3.5-flash")
DEFAULT_THINKING_LEVEL = os.getenv(GEMINI_THINKING_LEVEL_ENV, "MEDIUM")

# Agent Identity
AGENT_NAME = "Google Gemini Flash Reasoning Agent"
AGENT_VERSION = "1.0.0"

# Operational Limits & Timeouts
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "12.0"))
MAX_RETRIES = int(os.getenv("GEMINI_MAX_RETRIES", "2"))
MAX_INPUT_CHARS = int(os.getenv("GEMINI_MAX_INPUT_CHARS", "6000"))

# Execution Status Codes
STATUS_SUCCESS = "SUCCESS"
STATUS_DISABLED = "DISABLED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_ERROR = "ERROR"
STATUS_INVALID_SCHEMA = "INVALID_SCHEMA"
STATUS_SKIPPED_BENIGN = "SKIPPED_BENIGN"

# File Paths
REASONING_LOG_FILE = LOG_DIR / "llm_reasoning.json"
REASONING_RUNTIME_LOG = LOG_DIR / "llm_reasoning_runtime.log"

# Disclaimers
MOCK_REASONING_DISCLAIMER = "[OFFLINE DEMO / MOCK REASONING - NO EXTERNAL API CALL]"
