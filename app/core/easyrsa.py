"""
Cliente del helper privilegiado.

El panel corre sin privilegios y no puede tocar la PKI. Todas las operaciones
que necesitan root (revocar, restaurar, crear cliente, leer claves para armar
el .ovpn) se delegan en /usr/local/sbin/ovpn-web-helper vía sudo, que es lo
único que autoriza /etc/sudoers.d/ovpnweb.

El helper habla JSON por stdout. Aquí solo se valida el CN, se invoca y se
traduce el resultado.
"""

import json
import subprocess

from .validacion import validar_cn

TIMEOUT_POR_DEFECTO = 120


class ErrorHelper(Exception):
    """El helper privilegiado falló o devolvió un error"""


def _ejecutar(cfg, args, timeout=TIMEOUT_POR_DEFECTO):
    """
    Invoca el helper y devuelve su respuesta JSON.

    Nunca se usa shell=True ni se interpola nada en una cadena: los argumentos
    van como lista, así que un CN raro no puede convertirse en otro comando.
    """
    cmd = []
    if cfg.seguridad.usar_sudo:
        # -n: si sudo pidiera contraseña, falla en vez de quedarse colgado
        cmd += ["sudo", "-n"]
    cmd += [cfg.seguridad.helper] + list(args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise ErrorHelper("No se encontró el helper en %s" % cfg.seguridad.helper)
    except subprocess.TimeoutExpired:
        raise ErrorHelper("El helper no respondió en %s segundos" % timeout)

    if proc.returncode != 0:
        detalle = (proc.stderr or proc.stdout or "").strip()
        raise ErrorHelper(detalle or "El helper terminó con código %d" % proc.returncode)

    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise ErrorHelper("Respuesta no válida del helper: %s" % proc.stdout[:200])


def listar_certificados(cfg):
    """
    Devuelve {'validos': [...], 'revocados': [...]} ordenados alfabéticamente.
    """
    datos = _ejecutar(cfg, ["listar"], timeout=30)
    return {
        "validos": datos.get("validos", []),
        "revocados": datos.get("revocados", []),
    }


def revocar(cfg, cn):
    """Revoca el certificado del cliente y regenera la CRL"""
    cn = validar_cn(cn)
    return _ejecutar(cfg, ["revocar", cn])


def restaurar(cfg, cn):
    """Elimina la entrada revocada del índice y reemite el certificado"""
    cn = validar_cn(cn)
    return _ejecutar(cfg, ["restaurar", cn])


def crear_cliente(cfg, cn):
    """Emite un certificado de cliente nuevo (sin contraseña)"""
    cn = validar_cn(cn)
    return _ejecutar(cfg, ["crear", cn])


def generar_ovpn(cfg, cn):
    """
    Devuelve el contenido del archivo .ovpn del cliente, con los certificados
    y claves ya embebidos, listo para descargar.
    """
    cn = validar_cn(cn)
    datos = _ejecutar(cfg, ["ovpn", cn], timeout=30)
    contenido = datos.get("contenido")

    if not contenido:
        raise ErrorHelper("El helper no devolvió contenido para %s.ovpn" % cn)

    return contenido


def estado_servicio(cfg):
    """Devuelve {'activo': bool, 'estado': str} del servicio OpenVPN"""
    return _ejecutar(cfg, ["estado-servicio"], timeout=30)
