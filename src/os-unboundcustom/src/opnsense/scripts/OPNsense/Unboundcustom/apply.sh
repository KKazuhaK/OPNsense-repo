#!/bin/sh
exec /usr/local/bin/python3 /usr/local/opnsense/scripts/OPNsense/Unboundcustom/apply.py "${1:-apply}"
