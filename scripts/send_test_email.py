#!/usr/bin/env python3
"""
IntelliShield SDN — Standalone Test Email Script.

Run from terminal:
    python scripts/send_test_email.py
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from alerts.test_email import main

if __name__ == "__main__":
    main()
