#!/bin/sh

# Reopen /var/log/mihomo.log after newsyslog(8) has rotated it.
#
# The core and the watchdog write the log through daemon(8) supervisors, which
# keep it open. Without this, both went on writing into the rotated file, and
# every line after the first rotation was lost. newsyslog runs this instead of
# signalling a PID file (flag R in newsyslog.conf.d/mihomo.conf) and passes the
# signal number, which is ignored: the manager sends SIGHUP itself, and only to
# a supervisor it started with -H, because one without it would exit instead.
# Nothing running is a success.

exec /usr/local/bin/python3 /usr/local/opnsense/scripts/mihomo/mihomo.py reopen-log
