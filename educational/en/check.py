#!/usr/bin/env python3
"""Checks your solution to a lesson's "Your turn" exercise.

Usage, from the lesson folder:

    cp exercise.yml my_solution.yml      # edit my_solution.yml
    python3 ../check.py                  # checks my_solution.yml
    python3 ../check.py --all            # hard mode: every engine rule
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.exercises import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], lang='en'))
