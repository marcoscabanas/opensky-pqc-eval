#!/usr/bin/env python3
"""Step 1: validate the raw recording and prepare target/channel traces."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.main_experiment import main


if __name__ == "__main__":
    main(fixed_stage="prepare")
