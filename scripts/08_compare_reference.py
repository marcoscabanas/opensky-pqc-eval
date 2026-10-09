#!/usr/bin/env python3
"""Compare replay results with the matching Zenodo reference tables."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts._support.compare_reference import main


if __name__ == "__main__":
    raise SystemExit(main())
