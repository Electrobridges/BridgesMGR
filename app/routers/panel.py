"""Dashboard, conexiones activas, logs y configuración"""

from typing import List

from fastapi import APIRouter, Depends, Form, Query, Request

from .. import notificar
from ..auth import ip_cliente, solo_admin, usuario_actual, verificar_csrf
from ..core import logs as core_logs
from ..core.conexiones import obtener_conexiones, resumen_trafico, top_por_trafico
from ..core.easyrsa import ErrorHelper, estado_servicio, listar_certificados
from .comun import auditar, aviso, cfg, render

router = APIRouter()


@router.get("/")
def dashboard(request: Request, sesion=Depends(usuario_actual)):
    c = cfg(request)
    conexiones, fuente, errores = obtener_conexiones(c)

    try:
        certificados = listar_certificados(c)
    except ErrorHelper as e:
        certificados = {"validos": [], "revocados": []}
        errores.append("No se pudo consultar la PKI: %s" % e)

    try:
        servicio = estado_servicio(c)
    except ErrorHelper as e:
        servicio = {"activo": False, "estado": "desconocido", "servicio": c.openvpn.servicio}
        errores.append("No se pudo consultar el servicio: %s" % e)

    return render(request, "dashboard.html", {
        "resumen": resumen_trafico(conexiones),
        "top": top_por_trafico(conexiones),
        "certificados": certificados,
        "servicio": servicio,
        "fuente": fuente,
        "errores": errores,
    })


@router.get("/conexiones")
def pagina_conexiones(request: Request, sesion=Depends(usuario_actual)):
    return render(request, "conexiones.html", {})


@router.get("/conexiones/tabla")
def tabla_conexiones(request: Request, sesion=Depends(usuario_actual)):
    """Fragmento que HTMX refresca cada pocos segundos"""
    conexiones, fuente, errores = obtener_conexiones(cfg(request))

    return render(request, "partials/tabla_conexiones.html", {
        "conexiones": conexiones,
        "fuente": fuente,
        "errores": errores,
        "puede_desconectar": sesion["rol"] == "admin",
    })


@router.get("/logs")
def pagina_logs(request: Request, sesion=Depends(usuario_actual)):
    return render(request, "logs.html", {"ruta": cfg(request).openvpn.log_path})


@router.get("/logs/contenido")
def contenido_logs(
    request: Request,
    lineas: int = Query(200, ge=1, le=core_logs.MAX_LINEAS),
    filtro: str = Query(""),
    sesion=Depends(usuario_actual),
):
    c = cfg(request)
    error = None
    entradas = []

    try:
        entradas = core_logs.leer_log(c.openvpn.log_path, lineas, filtro)
    except FileNotFoundError as e:
        error = str(e)
    except PermissionError:
        error = (
            "Sin permisos para leer %s. El usuario del servicio debe pertenecer "
            "al grupo 'adm'." % c.openvpn.log_path
        )
    except OSError as e:
        error = "Error leyendo el log: %s" % e

    return render(request, "partials/log.html", {"entradas": entradas, "error": error})


@router.get("/configuracion")
def pagina_configuracion(request: Request, sesion=Depends(solo_admin)):
    """
    Cómo está montado el servidor: rutas de la PKI y los logs, puerto del
    management, estado de la unidad.

    solo_admin y no usuario_actual: un supervisor consulta el estado de la VPN,
    no el plano de la instalación. Nada de esto le hace falta para mirar quién
    está conectado, y le dice a un curioso por dónde empezar.
    """
    c = cfg(request)

    try:
        servicio = estado_servicio(c)
    except ErrorHelper as e:
        servicio = {"activo": False, "estado": str(e), "servicio": c.openvpn.servicio}

    return render(request, "configuracion.html", {
        "openvpn": c.openvpn,
        "cliente": c.cliente_ovpn,
        "servidor": c.servidor,
        "seguridad": c.seguridad,
        "servicio": servicio,
        "tamano_log": core_logs.tamano_log(c.openvpn.log_path),
        "notif": _estado_notificaciones(c),
    })


def _estado_notificaciones(c):
    """
    Lo que necesita la sección de notificaciones: qué está encendido y qué
    tiene destino configurado en el YAML.

    Las dos cosas por separado a propósito: un canal encendido sin destino no
    manda nada, y hay que poder decirlo en pantalla en vez de dejar que alguien
    lo dé por activo.
    """
    ruta = c.seguridad.db_path
    return {
        "canales": notificar.canales_activos(ruta),
        "eventos": notificar.eventos_activos(ruta),
        "categorias": notificar.CATEGORIAS,
        "configurado": {
            "correo": notificar.configurado(c, "correo"),
            "discord": notificar.configurado(c, "discord"),
        },
        "destinatarios": [d for d in (c.notificaciones.correo.destinatarios or []) if d],
    }


@router.post("/configuracion/notificaciones/probar")
def probar_notificaciones(
    request: Request,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Manda un aviso de prueba por cada canal que tenga destino en el YAML.

    Existe para no tener que provocar un incidente real para descubrir que el
    SMTP estaba mal escrito. Prueba los canales **configurados**, no los
    activados: lo normal es querer comprobarlo antes de encenderlos.

    Va en el hilo y no por la cola, porque lo único que se pide aquí es saber
    si llegó, y para eso hay que esperar la respuesta.
    """
    c = cfg(request)
    canales = {n: notificar.configurado(c, n) for n in ("correo", "discord")}

    if not any(canales.values()):
        return aviso(request, tipo="error", status_code=400, mensaje=(
            "No hay ningún canal con destino configurado. Rellena "
            "'notificaciones' en /etc/ovpn-web/config.yaml y reinicia el panel."
        ))

    enviados, fallos = notificar.avisar_ahora(
        c, canales,
        "[%s] Aviso de prueba" % c.servidor.host_bind,
        "\n".join([
            "Esto es una prueba lanzada desde el panel. No ha pasado nada.",
            "",
            "Usuario: %s" % sesion["usuario"],
            "Desde:   %s" % (ip_cliente(request) or "?"),
            "",
            "Si lo estás leyendo, este canal funciona.",
        ]),
    )

    auditar(request, sesion, "probar_notificaciones", None,
            resultado="ok" if enviados and not fallos else "error",
            detalle="ok=%s fallos=%s" % (",".join(enviados) or "ninguno",
                                         "; ".join(fallos) or "ninguno"))

    if enviados and not fallos:
        return aviso(request, "Enviado por %s. Si no llega, el problema está en "
                              "el destino, no en el panel." % " y ".join(enviados))
    if enviados:
        return aviso(request, tipo="aviso", mensaje=(
            "Enviado por %s, pero falló %s." % (" y ".join(enviados), "; ".join(fallos))))
    return aviso(request, tipo="error", status_code=400,
                 mensaje="No salió por ningún canal: %s" % "; ".join(fallos))


@router.post("/configuracion/notificaciones")
def guardar_notificaciones(
    request: Request,
    correo: str = Form(None),
    discord: str = Form(None),
    eventos: List[str] = Form(default=[]),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Guarda qué canales y qué categorías avisan.

    La regla que sostiene esto: **si el cambio reduce la vigilancia, el aviso
    sale antes de guardarlo y por los canales que todavía estaban activos.**

    Los destinos viven en config.yaml, que el panel no puede escribir, así que
    un atacante no puede redirigir las alertas a su buzón. Pero sí podría
    callarlas desde aquí, y esta regla hace que el último mensaje que salga sea
    justo el que dice que lo están haciendo. Se manda en el hilo, sin pasar por
    la cola: hay que saber si salió antes de aplicar el cambio.
    """
    c = cfg(request)
    ruta = c.seguridad.db_path

    antes = notificar.canales_activos(ruta)
    antes["eventos"] = notificar.eventos_activos(ruta)

    ahora = {"correo": bool(correo), "discord": bool(discord),
             "eventos": {e for e in eventos if e in notificar.CATEGORIAS}}

    apaga_canal = any(antes[c_] and not ahora[c_] for c_ in ("correo", "discord"))
    quita_evento = bool(antes["eventos"] - ahora["eventos"])
    fallos_aviso = []

    if apaga_canal or quita_evento:
        canales_previos = {c_: antes[c_] and notificar.configurado(c, c_)
                           for c_ in ("correo", "discord")}
        if any(canales_previos.values()):
            _, fallos_aviso = notificar.avisar_ahora(
                c, canales_previos,
                "[%s] Se están reduciendo las notificaciones" % c.servidor.host_bind,
                notificar.aviso_de_apagado(c, sesion["usuario"], ip_cliente(request),
                                           antes, ahora),
                grave=True,
            )

    notificar.guardar_ajustes(ruta, ahora["correo"], ahora["discord"], ahora["eventos"])
    auditar(request, sesion, "ajustar_notificaciones", None,
            detalle="canales=%s eventos=%s" % (
                ",".join(sorted(k for k in ("correo", "discord") if ahora[k])) or "ninguno",
                ",".join(sorted(ahora["eventos"])) or "ninguno"))

    mensaje = "Notificaciones guardadas."
    if apaga_canal or quita_evento:
        if fallos_aviso:
            mensaje = ("Guardado, pero el aviso previo de la desactivación no pudo "
                       "entregarse: %s" % "; ".join(fallos_aviso))
        else:
            mensaje = ("Guardado. Se envió antes el aviso de que se reduce la "
                       "vigilancia, por los canales que seguían activos.")

    return aviso(request, mensaje,
                 tipo="aviso" if fallos_aviso else "ok")
