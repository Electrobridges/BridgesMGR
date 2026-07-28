"""
Segundo factor TOTP (RFC 6238), implementado con la biblioteca estándar.

No hay dependencia nueva a propósito: el algoritmo son unas pocas líneas de
hmac y struct, y este proyecto ya evita traer código de fuera que no pueda
auditar de un vistazo (la CSP no admite CDNs y HTMX se verifica por hash).

Como el resto de app/core/, no importa nada de FastAPI: se prueba sin
levantar la web.

    secreto = generar_secreto()
    uri_otpauth(secreto, "daniel", "OpenVPN Manager")   # para la app del móvil
    verificar(secreto, "492039")                        # -> nº de paso o None

Sobre 'verificar': devuelve el **paso** (el intervalo de 30 s) que ha
coincidido en vez de un booleano. Quien llama debe guardarlo y rechazar
cualquier código de un paso ya usado; si no, un código interceptado sirve
durante toda su ventana de validez.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

# Valores del estándar, que es lo que esperan Google Authenticator, Aegis,
# FreeOTP y compañía. No los toques sin cambiar también lo que se le enseña
# al usuario al darse de alta.
PERIODO = 30
DIGITOS = 6
ALGORITMO = "SHA1"

# 160 bits, el tamaño recomendado por la RFC 4226 para claves HMAC-SHA1.
BYTES_SECRETO = 20

# Cuántos pasos de 30 s se aceptan hacia atrás y hacia delante. Con 1 se
# toleran ±30 s de desfase entre el reloj del servidor y el del móvil, que es
# el problema práctico más común. Subirlo amplía la ventana de un código
# robado.
VENTANA = 1


class TOTPInvalido(ValueError):
    """El código no es válido, o el secreto está mal formado"""


def generar_secreto():
    """Secreto nuevo en base32 sin relleno, que es lo que leen las apps"""
    return base64.b32encode(secrets.token_bytes(BYTES_SECRETO)).decode("ascii").rstrip("=")


def _clave(secreto):
    """Decodifica el secreto base32 tolerando minúsculas, espacios y relleno"""
    if not isinstance(secreto, str):
        raise TOTPInvalido("El secreto debe ser texto")

    # Se quita el relleno que pudiera traer: unas apps lo muestran con '=' y
    # otras sin él, y luego se recalcula. Si no, un secreto ya relleno acabaría
    # con el doble de '=' y no decodificaría.
    limpio = secreto.strip().replace(" ", "").replace("-", "").upper().rstrip("=")
    if not limpio:
        raise TOTPInvalido("El secreto está vacío")

    # base32 exige que la longitud sea múltiplo de 8; las apps lo muestran sin
    # el relleno, así que lo reponemos aquí.
    relleno = "=" * (-len(limpio) % 8)

    try:
        return base64.b32decode(limpio + relleno, casefold=True)
    except (ValueError, TypeError):
        raise TOTPInvalido("El secreto no es base32 válido")


def paso_actual(momento=None):
    """Número de intervalo de 30 s en el que estamos"""
    return int((momento if momento is not None else time.time()) // PERIODO)


def codigo(secreto, paso=None, momento=None):
    """Código de 6 dígitos para ese paso (por defecto, el de ahora)"""
    if paso is None:
        paso = paso_actual(momento)

    resumen = hmac.new(_clave(secreto), struct.pack(">Q", paso), hashlib.sha1).digest()

    # Truncado dinámico de la RFC 4226: los 4 bits bajos del último byte dicen
    # dónde empieza el número que se usa.
    desplazamiento = resumen[-1] & 0x0F
    trozo = struct.unpack(">I", resumen[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF

    return str(trozo % (10 ** DIGITOS)).zfill(DIGITOS)


def normalizar(entrada):
    """Quita espacios y guiones de lo que teclea el usuario"""
    if not isinstance(entrada, str):
        return ""
    return "".join(c for c in entrada if c.isdigit())


def verificar(secreto, entrada, momento=None, ventana=VENTANA, paso_minimo=None):
    """
    Comprueba un código y devuelve el paso que ha coincidido, o None.

    'paso_minimo' rechaza los pasos ya consumidos: pásale el último paso
    aceptado para ese usuario y un código no podrá reutilizarse dentro de su
    ventana de validez.
    """
    limpio = normalizar(entrada)
    if len(limpio) != DIGITOS:
        return None

    ahora = paso_actual(momento)

    for delta in range(-ventana, ventana + 1):
        paso = ahora + delta

        if paso_minimo is not None and paso <= paso_minimo:
            continue

        # compare_digest y no ==: el tiempo de comparación no debe depender de
        # cuántos dígitos se han acertado.
        if hmac.compare_digest(codigo(secreto, paso), limpio):
            return paso

    return None


def uri_otpauth(secreto, usuario, emisor="OpenVPN Manager"):
    """
    URI otpauth:// que entienden todas las apps de autenticación.

    Se le enseña al usuario como texto (y como QR si algún día se añade un
    generador): con ella o con el secreto a mano queda dado de alta.
    """
    etiqueta = urllib.parse.quote("%s:%s" % (emisor, usuario), safe="")
    parametros = urllib.parse.urlencode({
        "secret": secreto,
        "issuer": emisor,
        "algorithm": ALGORITMO,
        "digits": DIGITOS,
        "period": PERIODO,
    })
    return "otpauth://totp/%s?%s" % (etiqueta, parametros)


def formatear_secreto(secreto):
    """El secreto en grupos de 4, para poder teclearlo sin equivocarse"""
    limpio = secreto.strip().replace(" ", "")
    return " ".join(limpio[i:i + 4] for i in range(0, len(limpio), 4))
