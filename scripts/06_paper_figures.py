#!/usr/bin/env python3
"""Draw the four paper Results figures from completed reports."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts._support.paper_figures import main


if __name__ == "__main__":
    raise SystemExit(main())
