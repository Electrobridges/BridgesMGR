"""Dashboard, conexiones activas, logs y configuración"""

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, Form, Query, Request

from fastapi.responses import Response

from ..auth import ip_cliente, solo_admin, usuario_actual, verificar_csrf
from ..core import logs as core_logs
from ..core.conexiones import obtener_conexiones, resumen_trafico, top_por_trafico
from .. import db, estadisticas, exportacion, notificar, respaldar
from ..core import easyrsa, respaldos
from ..core.easyrsa import ErrorHelper, estado_servicio, listar_certificados
from ..core.parsers import format_bytes
from ..idiomas import N_, t, mensaje
from .comun import auditar, aviso, cfg, error_htmx, render

router = APIRouter()

# El valor interno de 'fuente' no cambia ('management', 'status' o None): lo
# que cambia es cómo se enseña. Las claves son las de siempre y los valores
# son el texto que va en pantalla, ya traducido.
_FUENTES = {
    "management": N_("management"),
    "status": N_("status"),
}


def _fuente_legible(fuente):
    """La fuente de datos como se enseña: traducida, o None si no se pudo leer."""
    return t(_FUENTES[fuente]) if fuente in _FUENTES else None


@router.get("/")
def dashboard(request: Request, sesion=Depends(usuario_actual)):
    c = cfg(request)
    conexiones, fuente, errores = obtener_conexiones(c)

    try:
        certificados = listar_certificados(c)
    except ErrorHelper as e:
        certificados = {"validos": [], "revocados": []}
        errores.append(t("No se pudo consultar la PKI: %(error)s", error=mensaje(e)))

    try:
        servicio = estado_servicio(c)
    except ErrorHelper as e:
        servicio = {"activo": False, "estado": t("desconocido"), "servicio": c.openvpn.servicio}
        errores.append(t("No se pudo consultar el servicio: %(error)s", error=mensaje(e)))

    return render(request, "dashboard.html", {
        "graficas": estadisticas.panel(c.seguridad.db_path),
        "resumen": resumen_trafico(conexiones),
        "top": top_por_trafico(conexiones),
        "certificados": certificados,
        "servicio": servicio,
        "fuente": _fuente_legible(fuente),
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
        "fuente": _fuente_legible(fuente),
        "errores": errores,
        "puede_desconectar": sesion["rol"] == "admin",
    })


def _ahora():
    """
    El reloj del visor de logs, aparte para que las pruebas lo puedan fijar.

    Hora local del servidor y no UTC a propósito: se compara de un vistazo con
    las marcas que el propio OpenVPN escribe en cada línea del log.
    """
    return datetime.now()


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
    except FileNotFoundError:
        # El error lleva el texto en español, que es un dato; lo que se
        # enseña se arma aquí, en el idioma de quien lo lee.
        error = t("No se encontró el archivo de log: %(ruta)s", ruta=c.openvpn.log_path)
    except PermissionError:
        error = t("Sin permisos para leer %(ruta)s. El usuario del servicio debe "
                  "pertenecer al grupo 'adm'.", ruta=c.openvpn.log_path)
    except OSError as e:
        error = t("Error leyendo el log: %(error)s", error=e)

    # El momento va SIEMPRE, también con error o sin líneas: es la única
    # señal de que la lectura ocurrió. Sin él, pulsar «Actualizar» con un log
    # que no ha crecido devuelve un fragmento idéntico y el botón parece roto.
    return render(request, "partials/log.html", {
        "entradas": entradas,
        "error": error,
        "momento": _ahora(),
    })


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
        # El estado se enseña traducido; str(e) es el texto del servidor, que
        # es un dato y va en español.
        servicio = {"activo": False, "estado": mensaje(e), "servicio": c.openvpn.servicio}

    return render(request, "configuracion.html", {
        "openvpn": c.openvpn,
        "cliente": c.cliente_ovpn,
        "servidor": c.servidor,
        "seguridad": c.seguridad,
        "servicio": servicio,
        "tamano_log": core_logs.tamano_log(c.openvpn.log_path),
        "notif": _estado_notificaciones(c),
        "respaldo": respaldar.ajustes(c.seguridad.db_path),
        "frecuencias": respaldar.frecuencias_traducidas(),
        "dir_respaldos": respaldar.directorio(c),
        "opciones_limpieza": _opciones_limpieza_traducidas(),
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
        "categorias": notificar.categorias_traducidas(),
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
        return error_htmx(request, t("Escribe %(palabra)s para confirmar. No se ha tocado nada.",
                                     palabra=CONFIRMA_ROTAR))

    # Se pregunta antes de rotar: después, los certificados siguen siendo los
    # mismos, pero conviene tener la lista para el aviso de reparto aunque la
    # PKI falle luego.
    try:
        validos = listar_certificados(c)["validos"]
    except ErrorHelper as e:
        return error_htmx(request, t("No se pudo consultar la PKI: %(error)s",
                                     error=mensaje(e)))

    try:
        resultado = easyrsa.rotar_tls_crypt(c)
    except ErrorHelper as e:
        auditar(request, sesion, "rotar_tls_crypt", None, "error", str(e))
        return error_htmx(request, t("No se pudo rotar la clave: %(error)s",
                                     error=mensaje(e)))

    auditar(request, sesion, "rotar_tls_crypt", None,
            detalle="huella=%s respaldo=%s afectados=%d"
                    % (resultado.get("huella", "?"), resultado.get("respaldo", "?"),
                       len(validos)))

    if validos:
        db.abrir_reparto(
            c.seguridad.db_path, db.MOTIVO_TLS_CRYPT, validos,
            detalle="Clave tls-crypt rotada. Los .ovpn anteriores ya no sirven.",
        )

    # 'texto' y no 'mensaje': el nombre de la función idiomas.mensaje() está
    # importado en este módulo, y una variable local con el mismo nombre
    # taparía la función en toda la función.
    texto = [t("Clave tls-crypt rotada (huella %(huella)s) y %(servicio)s reiniciado.",
               huella=resultado.get("huella", "?"),
               servicio=resultado.get("servicio", "OpenVPN"))]
    if validos:
        texto.append(t("Los %(n)s clientes necesitan un perfil nuevo: tienes la lista en "
                       "Clientes VPN.", n=len(validos)))
    else:
        texto.append(t("No hay clientes a los que repartir."))

    return aviso(request, " ".join(texto), tipo="aviso")


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
            t("No hay ningún canal con destino configurado. Rellena "
              "'notificaciones' en /etc/ovpn-web/config.yaml y reinicia el panel.")
        ))

    # El aviso sale en el idioma de la instalación, no en el del panel: lo lee
    # quien administre el servidor, no quien ha pulsado el botón.
    asunto, cuerpo = notificar.aviso_de_prueba(c, sesion["usuario"], ip_cliente(request))

    enviados, fallos = notificar.avisar_ahora(c, canales, asunto, cuerpo)

    auditar(request, sesion, "probar_notificaciones", None,
            resultado="ok" if enviados and not fallos else "error",
            detalle="ok=%s fallos=%s" % (",".join(enviados) or "ninguno",
                                         notificar.fallos_texto(fallos) or "ninguno"))

    if enviados and not fallos:
        return aviso(request, t("Enviado por %(canales)s. Si no llega, el problema está en "
                                "el destino, no en el panel.",
                                canales=notificar.texto_canales(enviados)))
    if enviados:
        return aviso(request, tipo="aviso", mensaje=(
            t("Enviado por %(canales)s, pero falló %(fallos)s.",
              canales=notificar.texto_canales(enviados),
              fallos=notificar.fallos_texto(fallos, traducir=True))))
    return aviso(request, tipo="error", status_code=400,
                 mensaje=t("No salió por ningún canal: %(fallos)s",
                           fallos=notificar.fallos_texto(fallos, traducir=True)))


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
            asunto, cuerpo = notificar.aviso_de_apagado(
                c, sesion["usuario"], ip_cliente(request), antes, ahora)
            _, fallos_aviso = notificar.avisar_ahora(
                c, canales_previos, asunto, cuerpo, grave=True,
            )

    notificar.guardar_ajustes(ruta, ahora["correo"], ahora["discord"], ahora["eventos"])
    auditar(request, sesion, "ajustar_notificaciones", None,
            detalle="canales=%s eventos=%s" % (
                ",".join(sorted(k for k in ("correo", "discord") if ahora[k])) or "ninguno",
                ",".join(sorted(ahora["eventos"])) or "ninguno"))

    texto = t("Notificaciones guardadas.")
    if apaga_canal or quita_evento:
        if fallos_aviso:
            texto = t("Guardado, pero el aviso previo de la desactivación no pudo "
                      "entregarse: %(fallos)s",
                      fallos=notificar.fallos_texto(fallos_aviso, traducir=True))
        else:
            texto = t("Guardado. Se envió antes el aviso de que se reduce la "
                      "vigilancia, por los canales que seguían activos.")

    return aviso(request, texto,
                 tipo="aviso" if fallos_aviso else "ok")


# ------------------------------------------------- respaldos y mantenimiento

EVENTO_RESPALDOS = "respaldos-actualizados"
CONFIRMA_LIMPIAR = "LIMPIAR"

# Cortes que se ofrecen para las dos purgas —la auditoría del panel y los
# sucesos de la VPN—. Lista cerrada y no un campo libre: 'días' llega de un
# formulario.
#
# El 0 es «todo, desde el primer registro», y está en la lista con su propio
# texto en pantalla justamente para que sea una elección y no un accidente: un
# 0 escrito a mano en un campo libre pediría lo mismo creyendo pedir otra cosa.
# Un valor que no esté aquí cae en CORTE_POR_DEFECTO, que es el más
# conservador de todos y nunca «todo».
TODO_EL_HISTORIAL = 0
CORTE_POR_DEFECTO = 30

OPCIONES_LIMPIEZA = (
    (30, N_("más de 30 días")),
    (90, N_("más de 90 días")),
    (180, N_("más de 180 días")),
    (365, N_("más de un año")),
    (TODO_EL_HISTORIAL, N_("todo, desde el primer registro")),
)
DIAS_LIMPIEZA = tuple(d for d, _ in OPCIONES_LIMPIEZA)


def _opciones_limpieza_traducidas():
    """
    Los cortes de la limpieza, con su texto ya traducido.

    Los NÚMEROS son los que van en el value del <option> y en la base: no se
    tocan. Solo el texto se traduce, y una clave que no esté en el diccionario
    sale tal cual: no puede reventar con un KeyError.
    """
    return tuple((valor, t(texto)) for valor, texto in OPCIONES_LIMPIEZA)


def _contexto_respaldos(request, errores=None):
    c = cfg(request)
    directorio = respaldar.directorio(c)
    errores = list(errores or [])
    copias = []

    try:
        copias = respaldos.listar(directorio)
    except respaldos.ErrorRespaldo as e:
        # El error se enseña traducido: str(e) es el texto del servidor, que es
        # un dato, y lo que ve quien está en la página lo lee en su idioma.
        errores.append(mensaje(e))

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
        texto = t("Respaldo automático desactivado. No se hará ninguna copia "
                  "nueva hasta que lo vuelvas a programar.")
    else:
        texto = t("Respaldo %(frecuencia)s a las %(hora)s, conservando %(copias)s "
                  "copias en %(ruta)s.",
                  frecuencia=respaldar.texto_frecuencia(puesto["frecuencia"]).lower(),
                  hora=puesto["hora"], copias=puesto["conservar"],
                  ruta=respaldar.directorio(c))

    return aviso(request, texto, refrescar=EVENTO_RESPALDOS)


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
        return error_htmx(request, t("No se pudo respaldar: %(error)s", error=mensaje(e)),
                          refrescar=EVENTO_RESPALDOS)

    auditar(request, sesion, "crear_respaldo", nombre,
            detalle="rotados=%s" % (",".join(borrados) or "ninguno"))

    # 'texto' y no 'mensaje': el nombre de la función idiomas.mensaje() está
    # importado en este módulo, y una variable local con el mismo nombre
    # taparía la función en toda la función.
    texto = t("Respaldo creado: %(nombre)s (en %(ruta)s).",
              nombre=nombre, ruta=respaldar.directorio(c))
    if borrados:
        texto += t(" Se han rotado %(n)s copia(s) antigua(s).", n=len(borrados))
    texto += t(" No se descarga desde aquí: lleva los hashes y los secretos TOTP.")

    return aviso(request, texto, refrescar=EVENTO_RESPALDOS)


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
        return error_htmx(request, mensaje(e), refrescar=EVENTO_RESPALDOS)

    if not habia:
        auditar(request, sesion, "borrar_respaldo", nombre, "error", "no existía")
        return error_htmx(request, t("Ese respaldo ya no estaba: %(nombre)s", nombre=nombre),
                          refrescar=EVENTO_RESPALDOS)

    auditar(request, sesion, "borrar_respaldo", nombre)
    return aviso(request, t("Respaldo borrado: %(nombre)s", nombre=nombre),
                 refrescar=EVENTO_RESPALDOS)


@router.get("/configuracion/exportar")
def exportar_datos(request: Request, sesion=Depends(solo_admin)):
    """
    Descarga un ZIP con la auditoría y los perfiles archivados, en CSV.

    Esto NO es un respaldo y no sirve para restaurar: los respaldos llevan
    hashes de contraseñas y secretos TOTP, y por eso se quedan en el servidor.
    Aquí solo sale lo que se puede mirar en una hoja de cálculo. Qué columnas
    entran está escrito una a una en app/exportacion.py.
    """
    c = cfg(request)
    nombre, contenido = exportacion.construir(c.seguridad.db_path)

    auditar(request, sesion, "exportar_datos", nombre,
            detalle="%d bytes" % len(contenido))

    return Response(
        content=contenido,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="%s"' % nombre,
            "Cache-Control": "no-store",
        },
    )


@router.post("/configuracion/limpieza")
def limpiar_base(
    request: Request,
    auditoria: str = Form(None),
    dias: int = Form(CORTE_POR_DEFECTO),
    eventos: str = Form(None),
    dias_eventos: int = Form(CORTE_POR_DEFECTO),
    sesiones: str = Form(None),
    compactar: str = Form(None),
    confirmacion: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Limpia la base: auditoría, sucesos de la VPN, caducados, y VACUUM.

    Pide escribir una palabra por lo mismo que la rotación de tls-crypt: borrar
    cualquiera de los dos historiales destruye el registro de quién hizo qué, y
    eso no puede quedar a un clic de distancia. La propia limpieza se anota en
    la auditoría que queda, y esa entrada dice cuántas filas se llevó por
    delante.

    Las dos purgas van con su propio corte y no comparten el desplegable: de
    los sucesos de la VPN entran muchos más y cunde tirarlos antes, mientras
    que la auditoría del panel es pequeña y conviene guardarla más tiempo.
    Un solo corte para ambas obligaría a elegir el peor de los dos.

    Los sucesos de la VPN no se recuperan borrándolos por error: el log del que
    salieron lo vacía logrotate cada semana, así que lo que se tire aquí se
    tira para siempre. Por eso también se purgan a mano, con su palabra y su
    corte, y no hay ninguna limpieza automática que corra sola por detrás.

    Los perfiles archivados no se tocan: son el historial de quién tuvo
    certificado, y ocupan tres columnas de texto.
    """
    c = cfg(request)
    ruta = c.seguridad.db_path

    if confirmacion.strip() != CONFIRMA_LIMPIAR:
        return error_htmx(request, t("Escribe %(palabra)s para confirmar. No se ha tocado "
                                    "nada.", palabra=CONFIRMA_LIMPIAR))

    if dias not in DIAS_LIMPIEZA:
        dias = CORTE_POR_DEFECTO

    if dias_eventos not in DIAS_LIMPIEZA:
        dias_eventos = CORTE_POR_DEFECTO

    if not (auditoria or eventos or sesiones or compactar):
        return error_htmx(request, t("No has marcado nada que limpiar."))

    hecho = []
    detalle = []

    if auditoria:
        filas = db.purgar_auditoria(ruta, dias)
        if dias == TODO_EL_HISTORIAL:
            hecho.append(t("%(n)s entrada(s) de auditoría, el historial entero", n=filas))
        else:
            hecho.append(t("%(n)s entrada(s) de auditoría de más de %(dias)s días",
                           n=filas, dias=dias))
        detalle.append("auditoria=%d corte=%s"
                       % (filas, "todo" if dias == TODO_EL_HISTORIAL else "%dd" % dias))

    if eventos:
        filas = db.purgar_eventos_vpn(ruta, dias_eventos)
        if dias_eventos == TODO_EL_HISTORIAL:
            hecho.append(t("%(n)s suceso(s) de la VPN, el historial entero", n=filas))
        else:
            hecho.append(t("%(n)s suceso(s) de la VPN de más de %(dias)s días",
                           n=filas, dias=dias_eventos))
        detalle.append("eventos_vpn=%d corte=%s"
                       % (filas, "todo" if dias_eventos == TODO_EL_HISTORIAL
                          else "%dd" % dias_eventos))

    if sesiones:
        caducadas = db.purgar_sesiones(ruta)
        pendientes = db.purgar_logins_pendientes(ruta)
        intentos = db.purgar_intentos(ruta)
        hecho.append(t("%(caducadas)s sesión(es) caducadas, %(pendientes)s login(s) a medias "
                       "y %(intentos)s contador(es) de intentos",
                       caducadas=caducadas, pendientes=pendientes, intentos=intentos))
        detalle.append("sesiones=%s pendientes=%s intentos=%s"
                       % (caducadas, pendientes, intentos))

    if compactar:
        liberado = db.compactar(ruta)
        hecho.append(t("y se han devuelto %(bytes)s al disco", bytes=format_bytes(liberado)))
        detalle.append("vacuum=%d" % liberado)

    auditar(request, sesion, "limpiar_base", None, detalle=" ".join(detalle))

    return aviso(request, t("Limpieza hecha: %(detalle)s.", detalle="; ".join(hecho)))
