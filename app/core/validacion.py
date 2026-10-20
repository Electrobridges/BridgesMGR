"""
Validación de entradas que acaban en llamadas a subprocess o en rutas de disco.

Este módulo es la frontera de seguridad del panel: todo Common Name que llegue
desde el navegador pasa por aquí antes de tocar easyrsa o el sistema de
archivos. Nunca construyas un comando ni una ruta con un CN sin validar.
"""

import re

from ..idiomas import MensajeError, N_

# EasyRSA acepta CNs bastante libres, pero nosotros restringimos a propósito:
# sin espacios, sin barras, sin puntos iniciales o finales. Así un CN jamás
# puede convertirse en un argumento extra, en una opción (-rf) ni en '../'.
_CN_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')

# Nombres que nunca deben tocarse desde el panel
_RESERVADOS = {'server', 'ca'}


class CNInvalido(MensajeError):
    """
    El Common Name no supera la validación.

    Es un MensajeError: guarda el texto en español y sus huecos, así que
    str(e) va a la auditoría y logs en español y mensaje(e) se enseña en el
    idioma de quien lo lee. Sigue siendo un ValueError, de modo que los
    `except ValueError` de siempre lo siguen cogiendo.
    """


def validar_cn(cn):
    """
    Comprueba que el Common Name es seguro para pasar a easyrsa.

    Devuelve el CN tal cual si es válido; lanza CNInvalido si no.
    """
    if not isinstance(cn, str):
        raise CNInvalido(N_("El nombre de usuario debe ser texto"))

    cn = cn.strip()

    if not cn:
        raise CNInvalido(N_("El nombre de usuario no puede estar vacío"))

    if len(cn) > 64:
        raise CNInvalido(N_("El nombre de usuario no puede superar 64 caracteres"))

    if not _CN_RE.match(cn):
        raise CNInvalido(
            N_("Solo se permiten letras, números, punto, guion y guion bajo, "
               "empezando y terminando en letra o número")
        )

    if cn.lower() in _RESERVADOS:
        raise CNInvalido(N_("'%(cn)s' es un nombre reservado del servidor"), cn=cn)

    return cn


def es_cn_valido(cn):
    """Versión booleana de validar_cn(), para filtrar listas sin excepciones"""
    try:
        validar_cn(cn)
        return True
    except CNInvalido:
        return False
