#!/bin/sh
set -o errexit
set -o nounset
set -o pipefail

# Default PUID and PGID if not provided
export PUID=${PUID:-1000}
export PGID=${PGID:-1000}

export SYNC_PORT=${SYNC_PORT:-8080}
export SYNC_BASE=${SYNC_BASE:-/anki_data}

# Check if group exists, create if not
if ! getent group anki-group > /dev/null 2>&1; then
    addgroup -g "$PGID" anki-group
fi

# Check if user exists, create if not
if ! id -u anki > /dev/null 2>&1; then
    adduser -D -H -u "$PUID" -G anki-group anki
fi

# Fix ownership of mounted volumes
mkdir -p "$SYNC_BASE"
chown anki:anki-group "$SYNC_BASE"

# Run the provided command as the `anki` user
exec su-exec anki "$@"
