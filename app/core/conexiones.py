"""
Obtención de conexiones activas con fallback explícito.

Misma lección que en el CLI: cuando ambas vías fallan hay que decir por qué,
no devolver una lista vacía que parece "no hay nadie conectado".
"""

import time

from .mgmt import ErrorManagement, obtener_conexiones as _mgmt_conexiones
from .parsers import parse_status_text


def leer_status(ruta):
    """Lee y parsea el archivo de status. Propaga los errores de lectura."""
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        return parse_status_text(f.read())


def segundos_conectado(conexion, ahora=None):
    """
    Cuánto lleva dentro esta conexión, en segundos, o None si no se puede
    afirmar.

    None y no un número raro cuando la resta sale negativa: pasa si al servidor
    le cambian la hora, o si el status v3 no trae el epoch y la fecha escrita
    se leyó con otra zona horaria. Es el mismo criterio que sigue
    eventos_vpn._segundos con las duraciones de sesión.
    """
    epoch = conexion.get("connected_since_epoch")
    if not epoch:
        return None

    total = int((time.time() if ahora is None else ahora) - epoch)
    return total if total >= 0 else None


def anotar_duraciones(conexiones, ahora=None):
    """
    Añade 'connected_seconds' a cada conexión y devuelve la misma lista.

    Se hace aquí y no en el parser porque el parser solo dice lo que pone el
    archivo, y esto depende de qué hora es ahora. Colgado del punto de entrada
    único, las dos vías —management y archivo de status— lo traen igual y
    ninguna vista tiene que volver a mirar el reloj por su cuenta.

    La clave va en inglés como el resto de las del dict de conexión, por
    compatibilidad con el CLI del que están portadas.
    """
    for c in conexiones:
        c["connected_seconds"] = segundos_conectado(c, ahora)

    return conexiones


def obtener_conexiones(cfg):
    """
    Devuelve (conexiones, fuente, errores).

    fuente es 'management', 'status' o None. errores es una lista de mensajes
    legibles explicando qué vía falló, para mostrarlos en la interfaz.
    """
    ovpn = cfg.openvpn
    errores = []

    try:
        conexiones = _mgmt_conexiones(ovpn.mgmt_host, ovpn.mgmt_port)
        return anotar_duraciones(conexiones), "management", errores
    except ErrorManagement as e:
        errores.append(str(e))

    try:
        return anotar_duraciones(leer_status(ovpn.status_path)), "status", errores
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
