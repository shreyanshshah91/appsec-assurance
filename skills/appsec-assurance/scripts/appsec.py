#!/usr/bin/env python3
"""Entry point for the appsec-assurance engine. Run with --help for usage."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from appsec.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
