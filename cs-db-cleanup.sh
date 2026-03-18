#!/bin/sh
#
# CrowdSec Database Maintenance (Auto-Detect Native/Docker)

set -e

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# Default configuration (can be overridden by args)
CONTAINER_NAME="${CONTAINER_NAME:-crowdsec}"
DB_PATH="${DB_PATH:-/var/lib/crowdsec/data/crowdsec.db}"
SIZE_THRESHOLD_MB="${1:-200}"
MAX_AGE="${2:-48h}"

log "=== CrowdSec DB Maintenance ==="
log "Threshold: ${SIZE_THRESHOLD_MB}MB"
log "Max Age:   $MAX_AGE"

# Detect mode (native vs docker)
MODE="unknown"
if command -v cscli >/dev/null 2>&1 && [ -d "/etc/crowdsec" ]; then
    MODE="native"
    log "Mode:      Native (Host)"
    log "DB Path:   $DB_PATH"

    # Prerequisite check for native mode
    if ! command -v sqlite3 >/dev/null 2>&1; then
        log "Error: 'sqlite3' is not installed on this host."
        log "Please install it (e.g., 'sudo apt install sqlite3') to vacuum natively."
        exit 1
    fi
elif command -v docker >/dev/null 2>&1 && docker ps -q -f name="^${CONTAINER_NAME}$" >/dev/null 2>&1; then
    MODE="docker"
    log "Mode:      Docker (Container: $CONTAINER_NAME)"
    log "DB Path:   $DB_PATH"
else
    log "Error: Could not detect CrowdSec (neither native 'cscli' nor Docker container '$CONTAINER_NAME' found)."
    exit 1
fi
log "==============================="

# Get current database size
if [ "$MODE" = "native" ]; then
    SIZE_BYTES=$(wc -c < "$DB_PATH" 2>/dev/null || echo "0")
else
    SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < $DB_PATH" 2>/dev/null || echo "0")
fi

if [ "$SIZE_BYTES" -eq 0 ]; then
    log "Error: Could not read database file size at $DB_PATH. Does it exist?"
    exit 1
fi

SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
THRESHOLD_BYTES=$((SIZE_THRESHOLD_MB * 1024 * 1024))

log "Current database size: ${SIZE_MB}MB"

# Check if size exceeds threshold
if [ "$SIZE_BYTES" -lt "$THRESHOLD_BYTES" ]; then
    log "Database size (${SIZE_MB}MB) is under the threshold (${SIZE_THRESHOLD_MB}MB)."
    log "No maintenance required. Exiting."
    exit 0
fi

log "Threshold exceeded! Starting cleanup process..."

# Flush alerts older than MAX_AGE
log "[1/4] Flushing alerts older than $MAX_AGE..."
if [ "$MODE" = "native" ]; then
    cscli alerts flush --max-age "$MAX_AGE"
else
    docker exec "$CONTAINER_NAME" cscli alerts flush --max-age "$MAX_AGE"
fi
sleep 3

# Stop CrowdSec to release SQLite locks
log "[2/4] Stopping CrowdSec (Releasing SQLite locks)..."
if [ "$MODE" = "native" ]; then
    systemctl stop crowdsec
else
    docker stop "$CONTAINER_NAME"
fi
sleep 10

# Vacuum and optimize database
log "[3/4] Vacuuming and optimizing database (this may take a minute)..."
if [ "$MODE" = "native" ]; then
    sqlite3 "$DB_PATH" 'VACUUM; PRAGMA optimize;'
else
    docker run --rm --volumes-from "$CONTAINER_NAME" alpine sh -c \
      "apk add --no-cache sqlite && sqlite3 $DB_PATH 'VACUUM; PRAGMA optimize;'"
fi

# Start CrowdSec again
log "[4/4] Starting CrowdSec..."
if [ "$MODE" = "native" ]; then
    systemctl start crowdsec
else
    docker start "$CONTAINER_NAME"
fi
sleep 10

# Verify new database size
if [ "$MODE" = "native" ]; then
    NEW_SIZE_BYTES=$(wc -c < "$DB_PATH" 2>/dev/null || echo "0")
else
    NEW_SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < $DB_PATH" 2>/dev/null || echo "0")
fi
NEW_SIZE_MB=$((NEW_SIZE_BYTES / 1024 / 1024))

log "==============================="
log "Maintenance complete!"
log "Original size: ${SIZE_MB}MB"
log "New size:      ${NEW_SIZE_MB}MB"
echo
if [ "$NEW_SIZE_MB" -lt "$SIZE_THRESHOLD_MB" ]; then
    log "Database size is now under the threshold. Cleanup successful!"
else
    log "Warning: Database size is still above the threshold. Consider further actions."
fi
log "==============================="
