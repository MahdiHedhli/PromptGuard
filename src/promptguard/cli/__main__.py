"""Entry point so `python -m promptguard.cli` works."""

from __future__ import annotations

import sys

from promptguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
