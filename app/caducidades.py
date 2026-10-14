"""
Caducidad de los certificados: los de cliente, la CA y el del servidor.

Lo mismo que el vigilante ya hace con la CRL, aplicado a lo demás que caduca
solo. Los de cliente dejan fuera a una persona; la CA o el certificado del
servidor, a todas a la vez, y el error que ve el cliente no dice por qué.

Las fechas las da el helper (el panel no puede leer la PKI) y se guardan en
`ajustes`: la tabla de clientes las enseña sin tener que preguntarle a root
cada 30 segundos. Se refrescan cada pocas horas y tras cada cambio en la PKI.
"""

import json
from datetime import datetime, timedelta, timezone

from . import db, notificar
from .core import easyrsa, salud

AJUSTE_CACHE = "caducidades_cache"
AJUSTE_AVISOS = "caducidades_avisos"

# Cada cuánto se vuelve a preguntar. Una fecha de caducidad no cambia sola:
# solo cuando se emite o se revoca algo, y entonces se invalida a mano.
REFRESCO = timedelta(hours=6)

# A partir de cuántos días se enseña en la tabla de clientes.
VISIBLE_DIAS = 30


def _a_fecha(iso):
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def dias_restantes(iso, ahora=None):
    fecha = _a_fecha(iso)
    if fecha is None:
        return None
    ahora = ahora or datetime.now(timezone.utc)
    return int((fecha - ahora).total_seconds() // 86400)


def cache(ruta):
    """Lo último que dijo el helper: {'leido': iso, 'datos': {...}} o None."""
    try:
        return json.loads(db.obtener_ajuste(ruta, AJUSTE_CACHE, "") or "null")
    except ValueError:
        return None


def invalidar(ruta):
    """Tras emitir, revocar o restaurar: la próxima vuelta vuelve a preguntar."""
    db.guardar_ajuste(ruta, AJUSTE_CACHE, "")


def refrescar(cfg, ahora=None, forzar=False):
    ruta = cfg.seguridad.db_path
    ahora = ahora or datetime.now(timezone.utc)
    actual = cache(ruta)
    if not forzar and actual:
        leido = datetime.fromisoformat(actual["leido"])
        if ahora - leido < REFRESCO:
            return actual["datos"]

    datos = easyrsa.caducidades(cfg)
    db.guardar_ajuste(ruta, AJUSTE_CACHE, json.dumps({"leido": ahora.isoformat(), "datos": datos}))
    return datos


def por_cliente(ruta, ahora=None):
    """{cn: días} de los que caducan en VISIBLE_DIAS o menos, para la tabla."""
    actual = cache(ruta)
    if not actual:
        return {}
    resultado = {}
    for cn, iso in (actual["datos"].get("clientes") or {}).items():
        dias = dias_restantes(iso, ahora)
        if dias is not None and dias <= VISIBLE_DIAS:
            resultado[cn] = dias
    return resultado


def _elementos(datos):
    """(clave, descripción, iso, afecta_a_todos) de todo lo que caduca."""
    if datos.get("ca"):
        yield "ca", "La CA", datos["ca"], True
    if datos.get("servidor"):
        yield "servidor", "El certificado del servidor (%s)" % datos.get("servidor_cn"), \
            datos["servidor"], True
    for cn, iso in sorted((datos.get("clientes") or {}).items()):
        yield "cliente:%s" % cn, "El certificado de '%s'" % cn, iso, False


def revisar(cfg, ahora=None):
    """
    Avisa al cruzar cada escalón (30, 14, 7, 3, 1 días, caducado), una vez.

    Mismo criterio que la CRL en el vigilante: sin escalones, o se avisa a
    diario durante un mes o no se avisa hasta que ya no da tiempo.
    """
    ruta = cfg.seguridad.db_path
    datos = refrescar(cfg, ahora)
    ahora = ahora or datetime.now(timezone.utc)

    try:
        avisados = json.loads(db.obtener_ajuste(ruta, AJUSTE_AVISOS, "") or "{}")
    except ValueError:
        avisados = {}

    vigentes = {}
    for clave, que, iso, todos in _elementos(datos):
        dias = dias_restantes(iso, ahora)
        if dias is None:
            continue
        umbral = salud.umbral_cruzado(dias)
        if umbral is None:
            continue
        vigentes[clave] = umbral
        anterior = avisados.get(clave)
        if anterior is not None and anterior <= umbral:
            continue

        fecha = _a_fecha(iso).strftime("%d/%m/%Y")
        if dias < 0:
            asunto = "[%s] %s HA CADUCADO" % (cfg.servidor.host_bind, que)
            estado = "caducó el %s." % fecha
        else:
            asunto = "[%s] %s caduca en %d día(s)" % (cfg.servidor.host_bind, que, dias)
            estado = "caduca el %s." % fecha

        if todos:
            consecuencia = ("Cuando caduque, NADIE podrá conectar a la VPN, y el error que "
                            "ve el cliente no lo dice. Hay que renovarlo en el servidor.")
        else:
            consecuencia = ("Cuando caduque, ese cliente no podrá conectar. Se renueva "
                            "reemitiendo su certificado: revocar y restaurar desde el panel, "
                            "y repartirle el .ovpn nuevo.")

        notificar.avisar(cfg, notificar.CERTIFICADOS, asunto,
                         "%s %s\n\n%s" % (que, estado, consecuencia),
                         grave=todos or dias < 7)

    # Lo que ya no está en ningún escalón —renovado, o revocado y fuera de la
    # lista— se olvida, para poder volver a avisar si hace falta.
    db.guardar_ajuste(ruta, AJUSTE_AVISOS, json.dumps(vigentes, sort_keys=True))
    return vigentes
