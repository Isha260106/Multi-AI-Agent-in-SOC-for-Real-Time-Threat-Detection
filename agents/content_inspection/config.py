"""
agents/content_inspection/config.py
===================================
Configuration for Content and Context Inspection Agent.
Multi-Agent SOC Project
"""

import os
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

AGENT_NAME = "Content & Context Inspection Agent"
RUNTIME_LOG = LOG_DIR / "content_inspection_runtime.log"

# Verdict Constants
VERDICT_EXFILTRATION_CRITICAL = "EXFILTRATION_CRITICAL"
VERDICT_GENUINE_USER_HIGH_VOLUME = "GENUINE_USER_HIGH_VOLUME"
VERDICT_SUSPICIOUS_UNVERIFIED = "SUSPICIOUS_UNVERIFIED"
VERDICT_BENIGN_ROUTINE = "BENIGN_ROUTINE"

# Critical Sensitive File Patterns & Signatures
CRITICAL_SENSITIVE_FILES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "config.py",
    "secrets.yaml",
    "secrets.json",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    ".bash_history",
    ".zsh_history",
    "authorized_keys",
    "known_hosts",
}

CRITICAL_SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".pkcs12",
    ".pfx",
    ".sql",
    ".mdf",
    ".kdbx",
    ".wallet",
}

# Benign Routine Large-Transfer File Extensions
ROUTINE_BENIGN_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".iso",
    ".deb",
    ".rpm",
    ".whl",
    ".tar.gz",
    ".zip",
    ".tar.xz",
    ".parquet",
    ".csv",
}

# Legitimate Processes commonly transferring high volumes
LEGITIMATE_TRANSFER_PROCESSES = {
    "rsync",
    "rclone",
    "dropbox",
    "git",
    "docker",
    "containerd",
    "apt-get",
    "apt",
    "dpkg",
    "firefox",
    "chrome",
    "brave",
    "mysqldump",
    "pg_dump",
    "borgbackup",
    "restic",
}

# Suspicious Exfiltration Tools / Reverse Shells
SUSPICIOUS_TRANSFER_PROCESSES = {
    "nc",
    "ncat",
    "netcat",
    "socat",
    "bash -i",
    "sh -i",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "curl",
    "wget",
}

# Known Trusted Cloud & Repository Domains / IP Networks
TRUSTED_DESTINATIONS = {
    "github.com",
    "raw.githubusercontent.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "packages.microsoft.com",
    "registry-1.docker.io",
    "pypi.org",
    "files.pythonhosted.org",
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "cloudflare.com",
}
