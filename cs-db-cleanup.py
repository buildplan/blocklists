#!/usr/bin/env python3

import os
import sys
import time
import argparse
import subprocess
import shutil
import shlex
from datetime import datetime

def log(msg: str):
    """Prints a timestamped log message."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {msg}")

def require_root():
    """Ensure the script is run with root privileges."""
    if os.geteuid() != 0:
        log("Error: This script must be run as root (or with sudo).")
        sys.exit(1)

def run_cmd(cmd: list, capture_output: bool = False) -> str | None:
    """Helper to run a subprocess command safely."""
    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None
        )
        return result.stdout.strip() if capture_output else None
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {' '.join(e.cmd)}")
        if capture_output and e.stderr:
            log(f"Error output: {e.stderr.strip()}")
        sys.exit(1)

def get_db_size_bytes(mode: str, container_name: str, db_path: str) -> int:
    """Retrieves the database size in bytes based on the mode."""
    if mode == "native":
        try:
            return os.path.getsize(db_path)
        except FileNotFoundError:
            return 0
    else:
        # Docker mode - safely quote the path
        safe_path = shlex.quote(db_path)
        cmd = ["docker", "exec", container_name, "sh", "-c", f"wc -c < {safe_path}"]
        try:
            result = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            return int(result.stdout.strip())
        except (subprocess.CalledProcessError, ValueError):
            return 0

def main():
    # Setup argument parsing
    parser = argparse.ArgumentParser(description="CrowdSec Database Maintenance")
    parser.add_argument("size_threshold_mb", type=int, nargs="?", default=200, help="Size threshold in MB (default: 200)")
    parser.add_argument("max_age", type=str, nargs="?", default="48h", help="Max age for alerts flush (default: 48h)")
    args = parser.parse_args()

    require_root()

    # Environment variables with fallbacks
    container_name = os.environ.get("CONTAINER_NAME", "crowdsec")
    db_path = os.environ.get("DB_PATH", "/var/lib/crowdsec/data/crowdsec.db")
    size_threshold_mb = args.size_threshold_mb
    max_age = args.max_age

    log("=== CrowdSec DB Maintenance ===")
    log(f"Threshold: {size_threshold_mb}MB")
    log(f"Max Age:   {max_age}")

    # Detect mode (native vs docker)
    mode = "unknown"
    is_native = bool(shutil.which("cscli") and os.path.isdir("/etc/crowdsec"))
    is_docker = bool(shutil.which("docker"))
    docker_running = False

    if is_docker:
        # Check if the specific container is running
        check_docker = subprocess.run(
            ["docker", "ps", "-q", "-f", f"name=^{container_name}$"],
            capture_output=True, text=True
        )
        docker_running = bool(check_docker.stdout.strip())

    if is_native:
        mode = "native"
        log("Mode:      Native (Host)")
        log(f"DB Path:   {db_path}")
        if not shutil.which("sqlite3"):
            log("Error: 'sqlite3' is not installed on this host.")
            log("Please install it (e.g., 'sudo apt install sqlite3') to vacuum natively.")
            sys.exit(1)

    elif is_docker and docker_running:
        mode = "docker"
        log(f"Mode:      Docker (Container: {container_name})")
        log(f"DB Path:   {db_path}")
    else:
        log(f"Error: Could not detect CrowdSec (neither native 'cscli' nor Docker container '{container_name}' found).")
        sys.exit(1)

    log("===============================")

    # Get current database size
    size_bytes = get_db_size_bytes(mode, container_name, db_path)

    if size_bytes == 0:
        log(f"Error: Could not read database file size at {db_path}. Does it exist?")
        sys.exit(1)

    size_mb = size_bytes // (1024 * 1024)
    threshold_bytes = size_threshold_mb * 1024 * 1024

    log(f"Current database size: {size_mb}MB")

    # Check if size exceeds threshold
    if size_bytes < threshold_bytes:
        log(f"Database size ({size_mb}MB) is under the threshold ({size_threshold_mb}MB).")
        log("No maintenance required. Exiting.")
        sys.exit(0)

    log("Threshold exceeded! Starting cleanup process...")

    # 1. Flush alerts
    log(f"[1/4] Flushing alerts older than {max_age}...")
    if mode == "native":
        run_cmd(["cscli", "alerts", "flush", "--max-age", max_age])
    else:
        run_cmd(["docker", "exec", container_name, "cscli", "alerts", "flush", "--max-age", max_age])
    time.sleep(3)

    # 2. Stop CrowdSec
    log("[2/4] Stopping CrowdSec (Releasing SQLite locks)...")
    if mode == "native":
        run_cmd(["systemctl", "stop", "crowdsec"])
    else:
        run_cmd(["docker", "stop", container_name])
    time.sleep(10)

    # 3. Vacuum database
    log("[3/4] Vacuuming and optimizing database (this may take a minute)...")
    if mode == "native":
        run_cmd(["sqlite3", db_path, "VACUUM; PRAGMA optimize;"])
    else:
        safe_path = shlex.quote(db_path)
        alpine_cmd = f"apk add --no-cache sqlite && sqlite3 {safe_path} 'VACUUM; PRAGMA optimize;'"
        run_cmd(["docker", "run", "--rm", "--volumes-from", container_name, "alpine", "sh", "-c", alpine_cmd])

    # 4. Start CrowdSec
    log("[4/4] Starting CrowdSec...")
    if mode == "native":
        run_cmd(["systemctl", "start", "crowdsec"])
    else:
        run_cmd(["docker", "start", container_name])
    time.sleep(10)

    # Verify new size
    new_size_bytes = get_db_size_bytes(mode, container_name, db_path)
    new_size_mb = new_size_bytes // (1024 * 1024)

    log("===============================")
    log("Maintenance complete!")
    log(f"Original size: {size_mb}MB")
    log(f"New size:      {new_size_mb}MB")
    print()

    if new_size_mb < size_threshold_mb:
        log("Database size is now under the threshold. Cleanup successful!")
    else:
        log("Warning: Database size is still above the threshold. Consider further actions.")
    log("===============================")

if __name__ == "__main__":
    main()
