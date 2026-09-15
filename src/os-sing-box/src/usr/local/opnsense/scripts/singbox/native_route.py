#!/usr/local/bin/python3
"""sing-box entry point for the shared FreeBSD route owner."""

import sys

from route_control import *


if __name__ == '__main__':
    sys.exit(main())
