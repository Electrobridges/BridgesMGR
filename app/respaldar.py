"""
Cuándo se respalda la base y dónde se guardan las copias.

El *cómo* está en core/respaldos.py, que no sabe de configuración ni de la
tabla `ajustes`. Aquí se decide.

Mismo reparto que en las notificaciones, y por el mismo motivo: **el directorio
va en config.yaml**, que el panel no puede escribir, y **el horario en la tabla
`ajustes`**, que sí. Así nadie redirige los respaldos a otro sitio desde la web
—serían la base entera saliendo por una ruta elegida por quien entró—, pero
cambiar la frecuencia no exige SSH.

Los respaldos **no se descargan desde el panel**. Contienen los hashes de las
contraseñas y los secretos TOTP de todas las cuentas: valen tanto como la base.
Se quedan en el servidor y se recogen por SSH. Lo que sí se puede bajar es la
exportación de `app/exportacion.py`, que lleva solo auditoría e historial.
"""

import os
from datetime import datetime, timedelta, timezone

from . import db
from .core import respaldos

# Cada cuánto. Cadenas fijas: se guardan en `ajustes` y se comparan con lo que
# llega del formulario, así que no pueden ser texto libre.
DESACTIVADO = "desactivado"
DIARIO = "diario"
SEMANAL = "semanal"

FRECUENCIAS = {
    DESACTIVADO: "Desactivado",
    DIARIO: "Cada día",
    SEMANAL: "Cada semana",
}

AJUSTE_FRECUENCIA = "respaldo_frecuencia"
AJUSTE_HORA = "respaldo_hora"
AJUSTE_CONSERVAR = "respaldo_conservar"
AJUSTE_ULTIMO = "respaldo_ultimo"

# De madrugada por defecto: copiar la base bloquea escrituras un instante, y a
# esa hora no hay nadie mirando el panel.
HORA_POR_DEFECTO = "03:00"

# Techo de lo que se puede pedir conservar. No es una regla de negocio: es que
# el campo llega de un formulario y un número absurdo llenaría el disco donde
# también vive la base.
MAX_CONSERVAR = 90


def directorio(cfg):
    """
    Dónde van los respaldos.

    Por defecto, junto a la base: /var/lib/ovpn-web/respaldos. Se deriva del
    db_path en vez de escribirlo fijo para que una instalación con la base en
    otro sitio no acabe respaldando a un directorio que no es suyo, y porque
    /var/lib/ovpn-web es lo único que la unidad de systemd deja escribir.
    """
    propio = (cfg.seguridad.respaldos_dir or "").strip()
    if propio:
        return propio

    return os.path.join(os.path.dirname(os.path.abspath(cfg.seguridad.db_path)),
                        "respaldos")


def ajustes(ruta_db):
    """Programación actual, ya saneada: lo que espera la plantilla"""
    frecuencia = db.obtener_ajuste(ruta_db, AJUSTE_FRECUENCIA, DESACTIVADO)
    if frecuencia not in FRECUENCIAS:
        frecuencia = DESACTIVADO

    return {
        "frecuencia": frecuencia,
        "hora": _hora_valida(db.obtener_ajuste(ruta_db, AJUSTE_HORA, HORA_POR_DEFECTO)),
        "conservar": _conservar_valido(
            db.obtener_ajuste(ruta_db, AJUSTE_CONSERVAR, respaldos.CONSERVAR_POR_DEFECTO)
        ),
        "ultimo": db.obtener_ajuste(ruta_db, AJUSTE_ULTIMO, ""),
    }


def guardar_ajustes(ruta_db, frecuencia, hora, conservar):
    """Guarda la programación saneada y devuelve cómo quedó"""
    if frecuencia not in FRECUENCIAS:
        frecuencia = DESACTIVADO

    db.guardar_ajuste(ruta_db, AJUSTE_FRECUENCIA, frecuencia)
    db.guardar_ajuste(ruta_db, AJUSTE_HORA, _hora_valida(hora))
    db.guardar_ajuste(ruta_db, AJUSTE_CONSERVAR, _conservar_valido(conservar))

    return ajustes(ruta_db)


def _hora_valida(texto):
    """
    'HH:MM' o la de por defecto. Nunca revienta: esto llega de un formulario.
    """
    try:
        horas, minutos = str(texto).split(":")
        horas, minutos = int(horas), int(minutos)
    except (AttributeError, TypeError, ValueError):
        return HORA_POR_DEFECTO

    if not (0 <= horas <= 23 and 0 <= minutos <= 59):
        return HORA_POR_DEFECTO

    return "%02d:%02d" % (horas, minutos)


def _conservar_valido(valor):
    try:
        conservar = int(valor)
    except (TypeError, ValueError):
        return respaldos.CONSERVAR_POR_DEFECTO

    return max(1, min(conservar, MAX_CONSERVAR))


def _a_local(texto_iso):
    """
    La marca del último respaldo, en hora local del servidor.

    Se guarda en UTC como todas las fechas de la base, pero la hora que elige
    el administrador es la del reloj que tiene delante, así que la comparación
    se hace en local.
    """
    if not texto_iso:
        return None

    try:
        marca = datetime.fromisoformat(texto_iso)
    except (TypeError, ValueError):
        return None

    if marca.tzinfo is None:
        return marca

    return marca.astimezone().replace(tzinfo=None)


def _ultimo_previsto(ahora, hora):
    """El cruce más reciente de esa hora del día, hoy o ayer"""
    horas, minutos = [int(p) for p in hora.split(":")]
    previsto = ahora.replace(hour=horas, minute=minutos, second=0, microsecond=0)

    if ahora < previsto:
        previsto -= timedelta(days=1)

    return previsto


def toca(frecuencia, hora, ultimo, ahora):
    """
    Si corresponde respaldar ahora mismo.

    'ultimo' y 'ahora' son datetime en hora local, sin zona.

    Se compara contra el último cruce de la hora elegida y no contra un
    'cada 24 horas' desde el respaldo anterior: así el respaldo de las 03:00
    sigue siendo el de las 03:00 aunque un día el panel estuviera parado a esa
    hora. Y si estuvo parado, al arrancar lo hace en cuanto puede, en vez de
    esperar a la madrugada siguiente.
    """
    if frecuencia == DESACTIVADO:
        return False

    previsto = _ultimo_previsto(ahora, hora)

    if ultimo is None:
        return True

    if ultimo >= previsto:
        return False

    # Semanal: además del cruce de hora, que hayan pasado siete días.
    if frecuencia == SEMANAL:
        return (ahora - ultimo) >= timedelta(days=7)

    return True


def ejecutar(cfg, ahora=None):
    """
    Hace un respaldo, rota los sobrantes y anota cuándo fue.

    Devuelve (nombre, borrados). Propaga ErrorRespaldo: quien llama decide si
    eso es un aviso en pantalla o una línea en el log del vigilante, pero nadie
    se traga el fallo. Un respaldo que falla en silencio es la peor versión de
    no tener respaldos, porque encima parece que los hay.
    """
    ahora = ahora or datetime.now()
    ruta_db = cfg.seguridad.db_path
    destino = directorio(cfg)
    config = ajustes(ruta_db)

    nombre = respaldos.crear(ruta_db, destino, ahora)
    borrados = respaldos.rotar(destino, config["conservar"])

    db.guardar_ajuste(ruta_db, AJUSTE_ULTIMO,
                      datetime.now(timezone.utc).isoformat())

    return nombre, borrados


def revisar(cfg, ahora=None):
    """
    Respalda si toca. Lo llama el vigilante en cada vuelta.

    Devuelve el nombre del respaldo si lo hizo, None si no tocaba.
    """
    ahora = ahora or datetime.now()
    config = ajustes(cfg.seguridad.db_path)

    if not toca(config["frecuencia"], config["hora"], _a_local(config["ultimo"]), ahora):
        return None

    nombre, _borrados = ejecutar(cfg, ahora)
    return nombre
