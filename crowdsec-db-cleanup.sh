#!/bin/sh
#
# CrowdSec Database Maintenance

set -e

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# Default configuration (can be overridden by environment variables or command-line arguments)
CONTAINER_NAME="${CONTAINER_NAME:-crowdsec}"
DB_PATH="${DB_PATH:-/var/lib/crowdsec/data/crowdsec.db}"
SIZE_THRESHOLD_MB="${1:-200}"
MAX_AGE="${2:-48h}"

log "=== CrowdSec DB Maintenance ==="
log "Container: $CONTAINER_NAME"
log "DB Path:   $DB_PATH"
log "Threshold: ${SIZE_THRESHOLD_MB}MB"
log "Max Age:   $MAX_AGE"
log "==============================="

# 1. Check if container is running
if ! docker ps -q -f name="^${CONTAINER_NAME}$" >/dev/null 2>&1; then
    log "Error: Container '$CONTAINER_NAME' is not running."
    exit 1
fi

# 2. Get current database size safely using wc -c inside the container
SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < $DB_PATH" 2>/dev/null || echo "0")

if [ "$SIZE_BYTES" -eq 0 ]; then
    log "Error: Could not read database file size at $DB_PATH. Does it exist?"
    exit 1
fi

# Convert bytes to MB
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
THRESHOLD_BYTES=$((SIZE_THRESHOLD_MB * 1024 * 1024))

log "Current database size: ${SIZE_MB}MB"

# 3. Compare current size against threshold
if [ "$SIZE_BYTES" -lt "$THRESHOLD_BYTES" ]; then
    log "Database size (${SIZE_MB}MB) is under the threshold (${SIZE_THRESHOLD_MB}MB)."
    log "No maintenance required. Exiting."
    exit 0
fi

log "Threshold exceeded! Starting cleanup process..."

# 4. Flush old alerts
log "[1/4] Flushing alerts older than $MAX_AGE..."
docker exec "$CONTAINER_NAME" cscli alerts flush --max-age "$MAX_AGE"
sleep 3

# 5. Stop CrowdSec
log "[2/4] Stopping '$CONTAINER_NAME' container (Releasing SQLite locks)..."
docker stop "$CONTAINER_NAME"
sleep 10

# 6. Vacuum and Optimize
log "[3/4] Vacuuming and optimizing database (this may take a minute)..."
docker run --rm --volumes-from "$CONTAINER_NAME" alpine sh -c \
  "apk add --no-cache sqlite && sqlite3 $DB_PATH 'VACUUM; PRAGMA optimize;'"

# 7. Start CrowdSec
log "[4/4] Starting '$CONTAINER_NAME' container..."
docker start "$CONTAINER_NAME"
sleep 10

# 8. Verify
NEW_SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < $DB_PATH" 2>/dev/null || echo "0")
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
