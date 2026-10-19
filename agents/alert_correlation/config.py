"""
Configuration for the Alert Correlation Agent (Stage 7).
"""
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

AGENT_NAME = "Alert Correlation Agent"
