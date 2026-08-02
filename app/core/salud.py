"""
Comprobaciones de salud que nadie mira hasta que es tarde.

La primera es la caducidad de la CRL, y merece explicación porque no es
evidente: **una CRL vencida hace que OpenVPN rechace TODAS las conexiones**, no
solo las de los certificados revocados. Y el síntoma no menciona la CRL por
ningún lado, así que se depura por el sitio equivocado durante un buen rato.

Llega sola, además. easyrsa emite la CRL con 180 días de validez por defecto, y
la regenera con ese plazo cada vez que se revoca a alguien. Una instalación que
revoque una vez pasa de una CRL a diez años a una de seis meses sin que nadie
lo decida ni lo vea.

Solo stdlib más `openssl`, que ya es dependencia del instalador. Parsear ASN.1
a mano para leer una fecha no compensa.
"""

import os
import re
import subprocess
from datetime import datetime, timezone

TIMEOUT = 10

# Umbrales de aviso, de más holgado a más urgente. Se avisa UNA vez al cruzar
# cada uno: sin escalones, o se avisa a diario durante seis meses o no se avisa
# hasta que ya no da tiempo a reaccionar.
UMBRALES = (30, 14, 7, 3, 1)


class SinCRL(Exception):
    """No se pudo leer la CRL. Lleva el motivo para poder enseñarlo."""


def _nextupdate(ruta):
    salida = subprocess.run(
        ["openssl", "crl", "-in", ruta, "-noout", "-nextupdate"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=TIMEOUT,
    )
    if salida.returncode != 0:
        detalle = salida.stderr.decode("utf-8", "replace").strip().splitlines()
        raise SinCRL(detalle[-1] if detalle else "openssl devolvió %d" % salida.returncode)

    texto = salida.stdout.decode("utf-8", "replace").strip()
    m = re.match(r"nextUpdate=(.+)$", texto)
    if not m:
        raise SinCRL("No se entiende la salida de openssl: %r" % texto)
    return m.group(1).strip()


def _a_fecha(texto):
    """
    'Jan 25 23:48:26 2027 GMT' -> datetime con zona.

    Se parsea aquí y no con 'date' del sistema porque esto tiene que correr
    igual en las pruebas, sin depender de qué formatos acepte el date de turno.
    """
    for formato in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            fecha = datetime.strptime(texto, formato)
            return fecha.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise SinCRL("Fecha de caducidad no reconocida: %r" % texto)


def caducidad_crl(ruta, ahora=None):
    """
    Devuelve (fecha, dias_restantes). Negativo si ya caducó.

    'ahora' es para las pruebas: sin él no se puede comprobar un umbral sin
    esperar meses.
    """
    if not ruta:
        raise SinCRL("No hay ruta de CRL configurada")
    if not os.path.isfile(ruta):
        raise SinCRL("No existe %s" % ruta)

    try:
        fecha = _a_fecha(_nextupdate(ruta))
    except (OSError, subprocess.SubprocessError) as e:
        raise SinCRL("No se pudo ejecutar openssl: %s" % e)

    ahora = ahora or datetime.now(timezone.utc)
    # //86400 y no .days: para un delta negativo, .days redondea hacia abajo y
    # "-0.5 días" saldría como -1, que se lee como "caducó ayer" cuando fue
    # hace unas horas.
    dias = int((fecha - ahora).total_seconds() // 86400)
    return fecha, dias


def umbral_cruzado(dias):
    """
    El umbral más urgente que corresponde a estos días restantes, o None.

    Devolver el más urgente y no el primero que encaje es lo que hace que
    reinstalar el panel tras un mes sin mirarlo avise de '3 días' y no de '30'.
    """
    if dias < 0:
        return 0
    for u in sorted(UMBRALES):
        if dias <= u:
            return u
    return None
