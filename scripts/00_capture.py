#!/usr/bin/env python3
"""Optional: record a new receiver stream; not needed to reproduce the paper."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts._support.capture import main


if __name__ == "__main__":
    raise SystemExit(main())
