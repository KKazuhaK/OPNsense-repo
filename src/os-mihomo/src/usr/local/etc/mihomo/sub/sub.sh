#!/bin/sh
# All subscription callers use the same state manager and log handling.
exec /usr/local/bin/python3 /usr/local/opnsense/scripts/mihomo/mihomo.py sub-update "$@"
