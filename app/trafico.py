"""
Tráfico por cliente: cuánto ha subido y bajado cada uno, por día.

OpenVPN solo da los bytes de la sesión en curso, que vuelven a cero en cada
reconexión. Para tener un histórico, el vigilante mira cada minuto y suma la
diferencia con la vista anterior de esa MISMA sesión —la reconoce por CN, IP
real con puerto y momento de conexión—. Una sesión nueva aporta todo lo que
lleva; una que ya estaba, solo lo que ha crecido.

La última vista se guarda en `ajustes`, no solo en memoria: si el panel se
reinicia, lo que pasó mientras estaba parado se suma igualmente en la
primera vuelta, en vez de perderse.

Y de aquí cuelgan las cuotas mensuales: quien supera la suya queda bloqueado
(el script de conexión lo rechaza y el vigilante lo saca) hasta que empieza
el mes siguiente, cuando se levanta solo.
"""

import json
from datetime import datetime

from . import db, notificar, politicas
from .core import easyrsa
from .core import politicas as pol

AJUSTE_ULTIMA = "trafico_ultima_vista"


def _clave(c):
    return "%s|%s|%s" % (c.get("user"), c.get("real_ip"), c.get("connected_since_epoch") or
                         c.get("connected_since"))


def muestrear(cfg, conexiones, ahora=None):
    """
    Suma al día de hoy lo que ha crecido cada sesión desde la vista anterior.

    Devuelve {cn: (recibido, enviado)} con lo sumado en esta vuelta.
    """
    ruta = cfg.seguridad.db_path
    try:
        anterior = json.loads(db.obtener_ajuste(ruta, AJUSTE_ULTIMA, "") or "{}")
    except ValueError:
        anterior = {}

    actual = {}
    deltas = {}
    for c in conexiones:
        cn = c.get("user")
        if not cn or cn == "UNDEF":
            continue
        clave = _clave(c)
        recibido, enviado = int(c.get("bytes_recv") or 0), int(c.get("bytes_sent") or 0)
        actual[clave] = [recibido, enviado]

        antes = anterior.get(clave)
        if antes and recibido >= antes[0] and enviado >= antes[1]:
            d = (recibido - antes[0], enviado - antes[1])
        else:
            # Sesión nueva, o un contador que ha vuelto atrás: lo que marca
            # ahora es todo tráfico que no se había contado.
            d = (recibido, enviado)

        if d[0] or d[1]:
            r, e = deltas.get(cn, (0, 0))
            deltas[cn] = (r + d[0], e + d[1])

    dia = (ahora or datetime.now()).strftime("%Y-%m-%d")
    db.sumar_trafico(ruta, dia, deltas)
    db.guardar_ajuste(ruta, AJUSTE_ULTIMA, json.dumps(actual))
    return deltas


def mes_actual(ahora=None):
    return (ahora or datetime.now()).strftime("%Y-%m")


def uso_mes(ruta, ahora=None):
    """{cn: bytes totales (subida + bajada)} del mes en curso."""
    return {cn: r + e for cn, (r, e) in db.trafico_mes(ruta, mes_actual(ahora)).items()}


def revisar_cuotas(cfg, ahora=None):
    """
    Bloquea a quien ha agotado su cuota del mes y desbloquea a quien ya no.

    El bloqueo va en la propia política ('bloqueo': 'cuota') y se aplica como
    cualquier otro cambio: así el script de conexión lo rechaza aunque el panel
    esté parado. Desbloquear al empezar el mes es lo mismo al revés.
    """
    ruta = cfg.seguridad.db_path
    todas = db.listar_politicas(ruta)
    uso = uso_mes(ruta, ahora)

    cambios = {}
    for cn, p in todas.items():
        p = pol.normalizar(p)
        limite = p["cuota_mb_mes"] * pol.BYTES_MB
        agotada = bool(limite) and uso.get(cn, 0) >= limite

        if agotada and p["bloqueo"] != pol.BLOQUEO_CUOTA:
            cambios[cn] = (dict(p, bloqueo=pol.BLOQUEO_CUOTA), "cuota_agotada")
        elif not agotada and p["bloqueo"] == pol.BLOQUEO_CUOTA:
            cambios[cn] = (dict(p, bloqueo=""), "cuota_restablecida")

    for cn, (nueva, accion) in sorted(cambios.items()):
        detalle = "%s de %s este mes" % (_legible(uso.get(cn, 0)),
                                         pol.describir_mb(nueva["cuota_mb_mes"]))
        try:
            politicas.aplicar(cfg, {cn: nueva}, usuario=notificar.ACTOR_SISTEMA)
        except (pol.PoliticaInvalida, easyrsa.ErrorHelper) as e:
            notificar.auditar_sistema(cfg, accion, cn, "error", str(e))
            continue
        notificar.auditar_sistema(cfg, accion, cn, detalle=detalle)

    return sorted(cambios)


def _legible(n):
    return bytes_decimales(n)


def bytes_decimales(n):
    """
    En las mismas unidades que la cuota (10^3, no 2^10).

    format_bytes, el del resto del panel, divide por 1024: con él, una cuota
    de 5 GB llena se leería como '4.66 GB' y parecería que aún queda.
    """
    for unidad in ("B", "KB", "MB", "GB"):
        if n < 1000:
            return ("%d %s" % (n, unidad)) if unidad == "B" else ("%.1f %s" % (n, unidad))
        n /= 1000
    return "%.1f TB" % n
