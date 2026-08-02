"""
Vigilante de la salud del servidor.

Las categorías de seguridad y certificados avisan colgadas de auditar(), porque
ocurren cuando alguien hace algo. Esta no: nadie *hace* que una CRL caduque ni
que OpenVPN se caiga. Hay que ir a mirar.

Corre en un hilo aparte y comprueba cada pocos minutos:

- **Caducidad de la CRL.** Una vencida hace que OpenVPN rechace TODAS las
  conexiones, no solo las revocadas, y el síntoma no la menciona. Llega sola:
  easyrsa la regenera con 180 días cada vez que se revoca a alguien.
- **Que el servicio siga en pie.** Solo se avisa al cambiar de estado, no en
  cada vuelta.

Lo arranca app/servidor.py y no crear_app(): así las pruebas, que construyen la
aplicación cientos de veces, no levantan un hilo cada vez.
"""

import threading
from datetime import datetime, timezone

from . import db, notificar
from .core import easyrsa, salud

# Cada cuánto se mira. Cinco minutos: lo que vigila cambia en días o de golpe,
# así que apurar más solo añade ruido y llamadas al helper.
INTERVALO = 300

# Estado entre vueltas, en `ajustes` para que sobreviva a un reinicio: si no,
# reiniciar el panel volvería a avisar de lo mismo.
AJUSTE_CRL = "vigilante_crl_umbral"
AJUSTE_SERVICIO = "vigilante_servicio"

_hilo = None
_parar = threading.Event()


def _revisar_crl(cfg):
    ruta_db = cfg.seguridad.db_path
    crl = "%s/pki/crl.pem" % cfg.openvpn.easyrsa_path.rstrip("/")

    try:
        fecha, dias = salud.caducidad_crl(crl)
    except salud.SinCRL as e:
        # No se avisa: sin CRL legible el problema es otro y ya lo canta el
        # comprobador. Avisar aquí llenaría el buzón en una instalación a medio
        # montar.
        db.guardar_ajuste(ruta_db, AJUSTE_CRL, "")
        return

    umbral = salud.umbral_cruzado(dias)
    anterior = db.obtener_ajuste(ruta_db, AJUSTE_CRL, "")

    if umbral is None:
        # Vuelve a haber holgura —alguien revocó y se regeneró—, así que se
        # rearma para poder avisar otra vez cuando toque.
        if anterior:
            db.guardar_ajuste(ruta_db, AJUSTE_CRL, "")
        return

    # Ya se avisó de este umbral o de uno más urgente
    if anterior and int(anterior) <= umbral:
        return

    db.guardar_ajuste(ruta_db, AJUSTE_CRL, str(umbral))

    cuando = fecha.strftime("%d/%m/%Y %H:%M UTC")
    if dias < 0:
        asunto = "[%s] LA CRL HA CADUCADO" % cfg.servidor.host_bind
        cuerpo = "\n".join([
            "La lista de revocación caducó el %s." % cuando,
            "",
            "OpenVPN está rechazando TODAS las conexiones, no solo las de los",
            "certificados revocados. Nadie puede entrar en la VPN.",
            "",
            "Se arregla revocando o restaurando cualquier cliente desde el panel:",
            "eso regenera la CRL. O en el servidor:",
            "  cd %s && ./easyrsa gen-crl" % cfg.openvpn.easyrsa_path,
            "  chmod 0644 %s" % crl,
        ])
    else:
        asunto = "[%s] La CRL caduca en %d día(s)" % (cfg.servidor.host_bind, dias)
        cuerpo = "\n".join([
            "La lista de revocación caduca el %s." % cuando,
            "",
            "Cuando caduque, OpenVPN rechazará TODAS las conexiones, no solo las",
            "de los certificados revocados, y el error no menciona la CRL.",
            "",
            "Se renueva regenerándola: revoca o restaura cualquier cliente desde",
            "el panel, o en el servidor:",
            "  cd %s && ./easyrsa gen-crl" % cfg.openvpn.easyrsa_path,
            "  chmod 0644 %s" % crl,
        ])

    notificar.avisar(cfg, notificar.SERVICIO, asunto, cuerpo, grave=(dias < 7))


def _revisar_servicio(cfg):
    ruta_db = cfg.seguridad.db_path

    try:
        estado = easyrsa.estado_servicio(cfg)
        activo = bool(estado.get("activo"))
        detalle = estado.get("estado", "?")
    except easyrsa.ErrorHelper as e:
        activo, detalle = False, str(e)

    anterior = db.obtener_ajuste(ruta_db, AJUSTE_SERVICIO, "")
    ahora = "activo" if activo else "caido"

    # Primera vuelta tras arrancar: se anota y no se avisa. Si no, reiniciar el
    # panel con el servicio ya caído mandaría un aviso que no es una novedad.
    if not anterior:
        db.guardar_ajuste(ruta_db, AJUSTE_SERVICIO, ahora)
        return

    if anterior == ahora:
        return

    db.guardar_ajuste(ruta_db, AJUSTE_SERVICIO, ahora)
    cuando = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    if activo:
        notificar.avisar(
            cfg, notificar.SERVICIO,
            "[%s] OpenVPN ha vuelto" % cfg.servidor.host_bind,
            "El servicio %s vuelve a estar activo.\n\nDesde: %s"
            % (cfg.openvpn.servicio, cuando),
        )
    else:
        notificar.avisar(
            cfg, notificar.SERVICIO,
            "[%s] OpenVPN NO está corriendo" % cfg.servidor.host_bind,
            "\n".join([
                "El servicio %s ha dejado de estar activo." % cfg.openvpn.servicio,
                "Estado: %s" % detalle,
                "Detectado: %s" % cuando,
                "",
                "Nadie puede conectarse a la VPN mientras siga así.",
                "  systemctl status %s" % cfg.openvpn.servicio,
            ]),
            grave=True,
        )


def _vuelta(cfg):
    for revision in (_revisar_crl, _revisar_servicio):
        try:
            revision(cfg)
        except Exception:  # noqa: BLE001
            # Una comprobación que falle no puede llevarse por delante a la
            # otra ni matar el hilo. Lo que importa es que el vigilante siga
            # vivo, que es lo único que puede avisar.
            pass


def _bucle(cfg):
    while not _parar.wait(INTERVALO):
        _vuelta(cfg)


def arrancar(cfg):
    """
    Levanta el vigilante. Lo llama app/servidor.py, no crear_app().

    Se hace una primera vuelta en el momento para dejar anotado el estado de
    partida sin avisar de él, y a partir de ahí se avisa solo de los cambios.
    """
    global _hilo

    if _hilo is not None and _hilo.is_alive():
        return _hilo

    _vuelta(cfg)

    _parar.clear()
    _hilo = threading.Thread(target=_bucle, args=(cfg,), name="vigilante",
                             daemon=True)
    _hilo.start()
    return _hilo
