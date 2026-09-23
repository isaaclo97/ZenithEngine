#!/usr/bin/env python3
"""Comprueba tu solución al ejercicio "Tu turno" de una lección.

Uso, desde la carpeta de la lección:

    cp ejercicio.yml mi_solucion.yml     # edita mi_solucion.yml
    python3 ../comprobar.py              # comprueba mi_solucion.yml
    python3 ../comprobar.py --todas      # modo difícil: todas las reglas del motor
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.exercises import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], lang='es'))
