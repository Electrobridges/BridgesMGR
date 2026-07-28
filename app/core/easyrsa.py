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

# Marca que le pide al helper cifrar la clave privada. Tiene que coincidir con
# MARCA_CLAVE del helper; es una palabra fija y nunca la contraseña.
MARCA_CLAVE = "con-clave"

MIN_CLAVE = 12


class ErrorHelper(Exception):
    """El helper privilegiado falló o devolvió un error"""


def _ejecutar(cfg, args, timeout=TIMEOUT_POR_DEFECTO, entrada=None):
    """
    Invoca el helper y devuelve su respuesta JSON.

    Nunca se usa shell=True ni se interpola nada en una cadena: los argumentos
    van como lista, así que un CN raro no puede convertirse en otro comando.

    'entrada' va por stdin y es por donde viaja la contraseña del certificado.
    Nunca como argumento: argv es público en /proc y cualquiera con una cuenta
    en el servidor podría leerla con un 'ps' en el momento justo.
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
            input=entrada,
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


class ClaveInvalida(ValueError):
    """La contraseña del certificado no cumple el mínimo"""


def _argumentos_de_emision(sub, cn, clave):
    """
    Monta (args, entrada) para los subcomandos que emiten una clave privada.

    La contraseña no aparece en 'args' ni aquí ni en ningún sitio: lo único que
    se le dice al helper por argumento es que va a haber una.
    """
    if clave is None:
        return [sub, cn], None

    if len(clave) < MIN_CLAVE:
        raise ClaveInvalida(
            "La contraseña del certificado debe tener al menos %d caracteres" % MIN_CLAVE
        )
    if "\n" in clave or "\r" in clave:
        # El helper lee la primera línea de stdin: un salto partiría la
        # contraseña en dos y cifraría con un trozo, en silencio.
        raise ClaveInvalida("La contraseña del certificado no puede tener saltos de línea")

    return [sub, cn, MARCA_CLAVE], clave + "\n"


def restaurar(cfg, cn, clave=None):
    """Elimina la entrada revocada del índice y reemite el certificado"""
    args, entrada = _argumentos_de_emision("restaurar", validar_cn(cn), clave)
    return _ejecutar(cfg, args, entrada=entrada)


def crear_cliente(cfg, cn, clave=None):
    """
    Emite un certificado de cliente nuevo.

    Con 'clave' la clave privada se guarda cifrada y OpenVPN la pedirá al
    conectar. Sin ella el perfil `.ovpn` es acceso directo a la VPN para
    cualquiera que se haga con el archivo.
    """
    args, entrada = _argumentos_de_emision("crear", validar_cn(cn), clave)
    return _ejecutar(cfg, args, entrada=entrada)


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
