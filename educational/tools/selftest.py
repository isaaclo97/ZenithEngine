#!/usr/bin/env python3
"""Maintainer self-test for the "Tu turno" / "Your turn" exercises.

For every lesson and language it checks that:
  1. the exercise statement FAILS the checker (there is something to fix), and
  2. the published solution PASSES it (the exercise can be solved).

Usage: python3 educational/tools/selftest.py [--online]

With --online, solutions are also checked against GitHub (every pinned hash
must be a published version, and the one named in its comment).
"""
import shutil
import sys
import tempfile
from pathlib import Path

EDUCATIONAL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDUCATIONAL))

from tools.exercises import FILES, check_file  # noqa: E402

SOLUTIONS_DIR = {'es': 'soluciones', 'en': 'solutions'}


def main():
    online = '--online' in sys.argv
    failures = 0
    for lang in ('es', 'en'):
        for lesson_dir in sorted((EDUCATIONAL / lang).glob('[0-9][0-9]-*')):
            exercise = lesson_dir / FILES[lang]['exercise']
            solution = EDUCATIONAL / lang / SOLUTIONS_DIR[lang] / f'{lesson_dir.name[:2]}.yml'
            if not exercise.exists() or not solution.exists():
                print(f'MISSING  {lang}/{lesson_dir.name}: exercise={exercise.exists()} solution={solution.exists()}')
                failures += 1
                continue
            with tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp) / lesson_dir.name
                work.mkdir()
                shutil.copy(exercise, work / FILES[lang]['exercise'])
                shutil.copy(solution, work / FILES[lang]['solution'])
                log = []
                exercise_problems = check_file(work / FILES[lang]['exercise'], lang, out=log.append)
                log.append('-' * 40)
                solution_problems = check_file(work / FILES[lang]['solution'], lang, out=log.append, online=online)
            ok = exercise_problems > 0 and solution_problems == 0
            print(f"{'OK  ' if ok else 'FAIL'}     {lang}/{lesson_dir.name}: "
                  f'exercise={exercise_problems} problem(s), solution={solution_problems}')
            if not ok:
                failures += 1
                print('\n'.join('         ' + line for line in '\n'.join(log).splitlines()))
    print(f'\n{failures} failure(s)')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
