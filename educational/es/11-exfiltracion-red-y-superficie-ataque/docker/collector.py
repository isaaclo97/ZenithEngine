#!/usr/bin/env python3
"""Receptor HTTP minimo que hace de "servidor del atacante": imprime en su
propia salida cualquier peticion que reciba, tal cual la veria un atacante
real recolectando datos exfiltrados. Solo escucha en la red interna y
aislada de docker-compose (network internal: true) -- nunca sale a
Internet."""
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode(errors='replace')
        print('=' * 60, flush=True)
        print(f'[collector] Petición recibida en {self.path}', flush=True)
        print(f'[collector] Body: {body}', flush=True)
        print('=' * 60, flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
        # Da tiempo a que la respuesta llegue al cliente antes de cerrar el proceso.
        threading.Timer(1.0, lambda: os._exit(0)).start()

    def log_message(self, format, *args):
        pass  # silenciar el log de acceso estandar, usamos el print de arriba


if __name__ == '__main__':
    print('[collector] Escuchando en 0.0.0.0:8080 (red interna, sin salida a Internet)...', flush=True)
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
