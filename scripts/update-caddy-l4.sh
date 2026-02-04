#!/bin/bash
#
# Script to rebuild Caddy with the L4 module and replace the system binary.
# Run monthly via cron, e.g.:
#   0 3 1 * * /path/to/update-caddy-l4.sh >> /var/log/caddy-update.log 2>&1
#
set -euo pipefail

# Ensure Go and xcaddy are in PATH (needed for cron)
export PATH="$PATH:/usr/local/go/bin:/root/go/bin:/home/${SUDO_USER:-root}/go/bin"

# Configuration
CADDY_BIN="/usr/bin/caddy"
BACKUP_DIR="/usr/bin"
BUILD_DIR="/tmp/caddy-build-$$"
LOG_PREFIX="[caddy-update]"

# Modules to include (add more as needed)
MODULES=(
    "github.com/mholt/caddy-l4"
)

log() {
    echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') $1"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

cleanup() {
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# Check for xcaddy
if ! command -v go &> /dev/null; then
    error_exit "go not found. Install Go first."
fi

# Update xcaddy to latest version
log "Updating xcaddy to latest version..."
if ! go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; then
    error_exit "Failed to install/update xcaddy"
fi
log "xcaddy updated: $(xcaddy version 2>/dev/null || echo 'version unknown')"

# Check we're running as root (needed to replace system binary)
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root (or with sudo)"
fi

log "Starting Caddy L4 rebuild..."

# Create temp build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Build xcaddy command with all modules
XCADDY_CMD="xcaddy build"
for module in "${MODULES[@]}"; do
    XCADDY_CMD+=" --with $module"
done

log "Building Caddy with modules: ${MODULES[*]}"
if ! $XCADDY_CMD; then
    error_exit "xcaddy build failed"
fi

# Verify the new binary works
if ! ./caddy version &> /dev/null; then
    error_exit "New Caddy binary failed version check"
fi

NEW_VERSION=$(./caddy version)
log "Built Caddy version: $NEW_VERSION"

# Check if L4 module is present
if ! ./caddy list-modules | grep -q "layer4"; then
    error_exit "L4 module not found in new build"
fi
log "L4 module verified"

# Get current version for comparison
if [[ -f "$CADDY_BIN" ]]; then
    CURRENT_VERSION=$($CADDY_BIN version 2>/dev/null || echo "unknown")
    log "Current version: $CURRENT_VERSION"
fi

# Stop Caddy
log "Stopping Caddy service..."
systemctl stop caddy || log "Warning: failed to stop caddy (may not be running)"

# Backup current binary with timestamp
BACKUP_NAME="caddy.backup.$(date '+%Y%m%d-%H%M%S')"
if [[ -f "$CADDY_BIN" ]]; then
    cp "$CADDY_BIN" "$BACKUP_DIR/$BACKUP_NAME"
    log "Backed up current binary to $BACKUP_DIR/$BACKUP_NAME"
fi

# Replace binary
mv ./caddy "$CADDY_BIN"
chmod 755 "$CADDY_BIN"
log "Replaced $CADDY_BIN"

# Start Caddy
log "Starting Caddy service..."
if ! systemctl start caddy; then
    log "ERROR: Failed to start Caddy with new binary!"
    log "Attempting rollback..."
    if [[ -f "$BACKUP_DIR/$BACKUP_NAME" ]]; then
        mv "$BACKUP_DIR/$BACKUP_NAME" "$CADDY_BIN"
        systemctl start caddy || true
        error_exit "Rolled back to previous binary. Check Caddy configuration."
    else
        error_exit "No backup available for rollback!"
    fi
fi

# Verify it's running
sleep 2
if systemctl is-active --quiet caddy; then
    log "Caddy is running successfully"
else
    error_exit "Caddy is not running after update"
fi

# Clean up old backups (keep last 3)
log "Cleaning old backups..."
ls -t "$BACKUP_DIR"/caddy.backup.* 2>/dev/null | tail -n +4 | xargs -r rm -f

log "Update complete! Caddy $NEW_VERSION with L4 module is now running."
