"""
Obtención de conexiones activas con fallback explícito.

Misma lección que en el CLI: cuando ambas vías fallan hay que decir por qué,
no devolver una lista vacía que parece "no hay nadie conectado".
"""

from .mgmt import ErrorManagement, obtener_conexiones as _mgmt_conexiones
from .parsers import parse_status_text


def leer_status(ruta):
    """Lee y parsea el archivo de status. Propaga los errores de lectura."""
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        return parse_status_text(f.read())


def obtener_conexiones(cfg):
    """
    Devuelve (conexiones, fuente, errores).

    fuente es 'management', 'status' o None. errores es una lista de mensajes
    legibles explicando qué vía falló, para mostrarlos en la interfaz.
    """
    ovpn = cfg.openvpn
    errores = []

    try:
        return _mgmt_conexiones(ovpn.mgmt_host, ovpn.mgmt_port), "management", errores
    except ErrorManagement as e:
        errores.append(str(e))

    try:
        return leer_status(ovpn.status_path), "status", errores
    except OSError as e:
        errores.append("No se pudo leer el archivo de status (%s): %s" % (ovpn.status_path, e))

    return [], None, errores


def resumen_trafico(conexiones):
    """Totales de tráfico para el dashboard"""
    recibido = sum(c.get("bytes_recv", 0) for c in conexiones)
    enviado = sum(c.get("bytes_sent", 0) for c in conexiones)

    return {
        "conectados": len(conexiones),
        "bytes_recv": recibido,
        "bytes_sent": enviado,
        "bytes_total": recibido + enviado,
    }


def top_por_trafico(conexiones, limite=5):
    """Clientes ordenados por tráfico total descendente"""
    return sorted(
        conexiones,
        key=lambda c: c.get("bytes_recv", 0) + c.get("bytes_sent", 0),
        reverse=True,
    )[:limite]
