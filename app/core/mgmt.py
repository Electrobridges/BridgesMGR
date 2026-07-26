"""
Cliente del management interface de OpenVPN.

Portado desde OpenVPN-Manager-CLI, incluyendo las dos correcciones que costó
encontrar allí: se pide 'status 3' (no 'status') y se lee en bucle hasta la
marca END, porque un solo recv() trunca la respuesta con varios clientes.
"""

import socket

from .parsers import parse_v3_output
from .validacion import validar_cn


class ErrorManagement(Exception):
    """Fallo al hablar con el management interface"""


def _conectar(host, puerto, timeout=5):
    """
    Abre una conexión con el management interface y descarta el banner.

    Devuelve el socket listo para recibir comandos.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, puerto))
    sock.recv(1024)  # banner ">INFO:OpenVPN Management Interface..."
    return sock


def _leer_hasta_end(sock):
    """
    Lee la respuesta del management hasta la marca END.

    Un solo recv() corta la respuesta a la mitad cuando hay varios clientes
    conectados, por eso acumulamos en bucle.
    """
    chunks = []

    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break

        if not data:
            break

        chunks.append(data.decode('utf-8', errors='replace'))
        texto = ''.join(chunks)

        if any(linea.strip() == 'END' for linea in texto.splitlines()):
            return texto

    return ''.join(chunks)


def obtener_conexiones(host, puerto, timeout=5):
    """
    Pide 'status 3' al management y devuelve la lista de conexiones.

    Lanza ErrorManagement si el socket falla.
    """
    try:
        sock = _conectar(host, puerto, timeout)
    except OSError as e:
        raise ErrorManagement(
            "Management interface (%s:%s) no disponible: %s" % (host, puerto, e)
        )

    try:
        sock.send(b"status 3\n")
        data = _leer_hasta_end(sock)
    except OSError as e:
        raise ErrorManagement("Error leyendo del management: %s" % e)
    finally:
        sock.close()

    return parse_v3_output(data)


def desconectar_cliente(host, puerto, cn, timeout=5):
    """
    Envía 'kill <cn>' al management para expulsar a un cliente conectado.

    Devuelve la respuesta cruda del servidor. El CN se valida antes de
    enviarlo aunque aquí no haya shell: un CN con salto de línea podría
    inyectar un segundo comando en el protocolo del management.
    """
    cn = validar_cn(cn)

    try:
        sock = _conectar(host, puerto, timeout)
    except OSError as e:
        raise ErrorManagement(
            "Management interface (%s:%s) no disponible: %s" % (host, puerto, e)
        )

    try:
        sock.send(("kill %s\n" % cn).encode())
        respuesta = sock.recv(1024).decode('utf-8', errors='replace').strip()
    except OSError as e:
        raise ErrorManagement("Error enviando kill: %s" % e)
    finally:
        sock.close()

    if 'SUCCESS' not in respuesta:
        raise ErrorManagement(respuesta or "El management no confirmó la desconexión")

    return respuesta
