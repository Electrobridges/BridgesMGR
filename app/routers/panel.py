"""Dashboard, conexiones activas, logs y configuración"""

from typing import List

from fastapi import APIRouter, Depends, Form, Query, Request

from fastapi.responses import Response

from ..auth import ip_cliente, solo_admin, usuario_actual, verificar_csrf
from ..core import logs as core_logs
from ..core.conexiones import obtener_conexiones, resumen_trafico, top_por_trafico
from .. import db, notificar, respaldar
from ..core import easyrsa, respaldos
from ..core.easyrsa import ErrorHelper, estado_servicio, listar_certificados
from .comun import auditar, aviso, cfg, error_htmx, render

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
        "respaldo": respaldar.ajustes(c.seguridad.db_path),
        "frecuencias": respaldar.FRECUENCIAS,
        "dir_respaldos": respaldar.directorio(c),
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


CONFIRMA_ROTAR = "ROTAR"


@router.post("/configuracion/tls-crypt/rotar")
def rotar_tls_crypt(
    request: Request,
    confirmacion: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Rota la clave tls-crypt del servidor.

    Deja fuera a TODOS los clientes de golpe: esa clave va embebida en cada
    .ovpn, así que ninguno de los repartidos vuelve a servir. Por eso no está
    en Clientes VPN junto a las acciones del día a día, exige escribir una
    palabra en vez de un [s/N], y al terminar abre el aviso de perfiles
    pendientes de repartir con todos los clientes válidos.

    El helper hace el trabajo delicado —respaldo, verificar el formato de lo
    generado antes de pisar lo que funciona, y restaurar si OpenVPN no vuelve a
    levantar—, porque la clave es de root y el panel no la alcanza.
    """
    c = cfg(request)

    if confirmacion.strip() != CONFIRMA_ROTAR:
        return error_htmx(request, "Escribe %s para confirmar. No se ha tocado nada."
                          % CONFIRMA_ROTAR)

    # Se pregunta antes de rotar: después, los certificados siguen siendo los
    # mismos, pero conviene tener la lista para el aviso de reparto aunque la
    # PKI falle luego.
    try:
        validos = listar_certificados(c)["validos"]
    except ErrorHelper as e:
        return error_htmx(request, "No se pudo consultar la PKI: %s" % e)

    try:
        resultado = easyrsa.rotar_tls_crypt(c)
    except ErrorHelper as e:
        auditar(request, sesion, "rotar_tls_crypt", None, "error", str(e))
        return error_htmx(request, "No se pudo rotar la clave: %s" % e)

    auditar(request, sesion, "rotar_tls_crypt", None,
            detalle="huella=%s respaldo=%s afectados=%d"
                    % (resultado.get("huella", "?"), resultado.get("respaldo", "?"),
                       len(validos)))

    if validos:
        db.abrir_reparto(
            c.seguridad.db_path, db.MOTIVO_TLS_CRYPT, validos,
            detalle="Clave tls-crypt rotada. Los .ovpn anteriores ya no sirven.",
        )

    mensaje = ("Clave tls-crypt rotada (huella %s) y %s reiniciado. "
               % (resultado.get("huella", "?"), resultado.get("servicio", "OpenVPN")))
    if validos:
        mensaje += ("Los %d clientes necesitan un perfil nuevo: tienes la lista en "
                    "Clientes VPN." % len(validos))
    else:
        mensaje += "No hay clientes a los que repartir."

    return aviso(request, mensaje, tipo="aviso")


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


# ------------------------------------------------- respaldos y mantenimiento

EVENTO_RESPALDOS = "respaldos-actualizados"


def _contexto_respaldos(request, errores=None):
    c = cfg(request)
    directorio = respaldar.directorio(c)
    errores = list(errores or [])
    copias = []

    try:
        copias = respaldos.listar(directorio)
    except respaldos.ErrorRespaldo as e:
        errores.append(str(e))

    return {
        "copias": copias,
        "dir_respaldos": directorio,
        "respaldo": respaldar.ajustes(c.seguridad.db_path),
        "errores_respaldo": errores,
    }


@router.get("/configuracion/respaldos/tabla")
def tabla_respaldos(request: Request, sesion=Depends(solo_admin)):
    """Fragmento con las copias que hay ahora mismo en el disco"""
    return render(request, "partials/tabla_respaldos.html",
                  _contexto_respaldos(request))


@router.post("/configuracion/respaldos")
def guardar_respaldos(
    request: Request,
    frecuencia: str = Form(respaldar.DESACTIVADO),
    hora: str = Form(respaldar.HORA_POR_DEFECTO),
    conservar: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Programa el respaldo automático.

    El horario vive en la tabla `ajustes` y no en config.yaml porque el panel no
    puede escribir ese archivo. El **directorio** sí está en el YAML, y no se
    toca desde aquí: si se pudiera elegir, quien entrara en el panel podría
    mandar copias enteras de la base a una ruta suya.
    """
    c = cfg(request)
    puesto = respaldar.guardar_ajustes(c.seguridad.db_path, frecuencia, hora, conservar)

    auditar(request, sesion, "ajustar_respaldos", None,
            detalle="frecuencia=%s hora=%s conservar=%d"
                    % (puesto["frecuencia"], puesto["hora"], puesto["conservar"]))

    if puesto["frecuencia"] == respaldar.DESACTIVADO:
        mensaje = ("Respaldo automático desactivado. No se hará ninguna copia "
                   "nueva hasta que lo vuelvas a programar.")
    else:
        mensaje = ("Respaldo %s a las %s, conservando %d copias en %s."
                   % (respaldar.FRECUENCIAS[puesto["frecuencia"]].lower(),
                      puesto["hora"], puesto["conservar"], respaldar.directorio(c)))

    return aviso(request, mensaje, refrescar=EVENTO_RESPALDOS)


@router.post("/configuracion/respaldos/ahora")
def respaldar_ahora(
    request: Request,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """Copia la base en el momento, sin esperar a la hora programada"""
    c = cfg(request)

    try:
        nombre, borrados = respaldar.ejecutar(c)
    except respaldos.ErrorRespaldo as e:
        auditar(request, sesion, "crear_respaldo", None, "error", str(e))
        return error_htmx(request, "No se pudo respaldar: %s" % e,
                          refrescar=EVENTO_RESPALDOS)

    auditar(request, sesion, "crear_respaldo", nombre,
            detalle="rotados=%s" % (",".join(borrados) or "ninguno"))

    mensaje = "Respaldo creado: %s (en %s)." % (nombre, respaldar.directorio(c))
    if borrados:
        mensaje += (" Se han rotado %d copia(s) antigua(s)." % len(borrados))
    mensaje += " No se descarga desde aquí: lleva los hashes y los secretos TOTP."

    return aviso(request, mensaje, refrescar=EVENTO_RESPALDOS)


@router.post("/configuracion/respaldos/borrar")
def borrar_respaldo(
    request: Request,
    nombre: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Borra una copia concreta.

    El nombre llega del formulario, así que core/respaldos lo valida contra la
    forma exacta que genera antes de tocar el disco: un '../..' saldría del
    directorio sin que os.path.join se queje.
    """
    c = cfg(request)

    try:
        habia = respaldos.borrar(respaldar.directorio(c), nombre)
    except respaldos.ErrorRespaldo as e:
        auditar(request, sesion, "borrar_respaldo", nombre, "error", str(e))
        return error_htmx(request, str(e), refrescar=EVENTO_RESPALDOS)

    if not habia:
        auditar(request, sesion, "borrar_respaldo", nombre, "error", "no existía")
        return error_htmx(request, "Ese respaldo ya no estaba: %s" % nombre,
                          refrescar=EVENTO_RESPALDOS)

    auditar(request, sesion, "borrar_respaldo", nombre)
    return aviso(request, "Respaldo borrado: %s" % nombre, refrescar=EVENTO_RESPALDOS)
