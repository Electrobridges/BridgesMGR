"""
Lectura del log de OpenVPN.

El servicio corre como 'ovpnweb', que el instalador añade al grupo 'adm'
(dueño de /var/log en Debian). Así el log se lee directamente, sin pasar por
el helper privilegiado.
"""

import os
from collections import deque

NIVELES = {
    "error": ("ERROR", "error", "TLS Error", "Cannot", "FATAL"),
    "aviso": ("WARNING", "warning", "Warn"),
    "conexion": ("Connected", "connected", "Initialization Sequence Completed",
                 "peer info", "SENT CONTROL"),
}

MAX_LINEAS = 2000


def clasificar(linea):
    """Etiqueta una línea de log para colorearla en la interfaz"""
    for nivel, marcas in NIVELES.items():
        if any(m in linea for m in marcas):
            return nivel
    return "info"


def leer_log(ruta, lineas=200, filtro=None):
    """
    Devuelve las últimas líneas del log, opcionalmente filtradas.

    Cada elemento es {'texto': str, 'nivel': str}. Lee en streaming con un
    deque acotado para no cargar en memoria un log de cientos de MB.
    """
    lineas = max(1, min(int(lineas), MAX_LINEAS))
    filtro = (filtro or "").strip().lower()

    if not os.path.exists(ruta):
        raise FileNotFoundError("No se encontró el archivo de log: %s" % ruta)

    ultimas = deque(maxlen=lineas)

    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        for linea in f:
            linea = linea.rstrip("\n")
            if filtro and filtro not in linea.lower():
                continue
            ultimas.append(linea)

    return [{"texto": l, "nivel": clasificar(l)} for l in ultimas]


def tamano_log(ruta):
    """Tamaño del log en bytes, o None si no se puede leer"""
    try:
        return os.path.getsize(ruta)
    except OSError:
        return None
