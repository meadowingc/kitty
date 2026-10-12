#!/bin/sh
set -eu
if [ ! -x /usr/local/sbin/update-caddy-l4 ]; then
    printf '%s\n' 'Install the reviewed independent Caddy updater before using this compatibility entrypoint.' >&2
    exit 1
fi
exec /usr/local/sbin/update-caddy-l4 "$@"
