"""
Administración del propio panel: usuarios con acceso y registro de auditoría.

Ojo con la diferencia: aquí se gestionan las cuentas que entran al PANEL, no
los clientes VPN. Esos están en routers/clientes.py.

Quién puede tocar a quién vive aquí y no en auth.py: solo_admin responde
"¿puede mutar el servidor?", que no depende de nadie más, mientras que esto
depende de la cuenta de destino y no cabe en una dependencia de FastAPI.

La jerarquía es de tres escalones (db.ROLES), pero el blindaje es de uno solo:
al superusuario solo lo administra el superusuario. Entre admins se administran
unos a otros, a propósito.
"""

from fastapi import APIRouter, Depends, Form, Request

from .. import db, eventos
from ..auth import solo_admin, usuario_actual, verificar_csrf
from ..core import eventos_vpn
from ..idiomas import N_, mensaje, nombre_rol, t
from .comun import auditar, aviso, cfg, error_htmx, paginar, render

router = APIRouter(prefix="/admin")

EVENTO_REFRESCO = "usuarios-actualizados"

# Los textos fijos de este módulo se marcan con N_() donde se definen y se
# traducen con t() donde se enseñan: en una constante de módulo, t() se
# evaluaría al importar, una sola vez y en el idioma por defecto.
SIN_MANDO = N_("No puedes dejar el panel sin ninguna cuenta capaz de administrarlo")

# El motivo por el que no se puede administrar la cuenta blindada. Va con un
# hueco con nombre para poder enseñarlo traducido sin perder el nombre de
# quien lo va a leer.
VETO_SUPERUSUARIO = N_(
    "'%(usuario)s' es el superusuario: solo esa cuenta puede administrarse a "
    "sí misma. Desde el servidor queda la CLI."
)


def _ultimo_al_mando(ruta, registro):
    """
    Si quitar de en medio a esta cuenta dejaría el panel sin quien lo administre.

    Pide que la cuenta esté activa: degradar o borrar a un admin ya desactivado
    no resta a nadie del mando, y sin esa condición el aviso saltaba igual y
    bloqueaba una limpieza legítima.

    Hoy no llega a dispararse por ninguna ruta, y conviene saber por qué en vez
    de descubrirlo: quien actúa ya es una cuenta de mando activa y las tres
    rutas le impiden apuntarse a sí misma, así que si el destino también está
    al mando y activo son dos, nunca uno. Se queda como red por debajo de esos
    guardas: si algún día se relaja el "no puedes tocarte a ti mismo", esto es
    lo que evita que el panel se quede huérfano. Se prueba directamente en
    tests/test_jerarquia.py, no a través de una ruta que no puede alcanzarlo.
    """
    return (registro["activo"]
            and registro["rol"] in db.ROLES_MANDO
            and db.contar_mando_activo(ruta) <= 1)


def _veto(sesion, registro):
    """
    Motivo por el que esta sesión no puede administrar esa cuenta, o None.

    El superusuario es la única cuenta blindada, y lo está contra todo: rol,
    contraseña, activación, borrado y segundo factor. Si un admin pudiera
    cambiarle la contraseña, sería superusuario en dos pasos.

    Devuelve el texto del motivo con el hueco del nombre sin rellenar: así el
    mismo texto sirve para las dos cosas, y cada una lo usa como le toca. En la
    pantalla se enseña traducido (t(motivo, usuario=...)); en la auditoría se
    queda en español, que es como se guardan los datos.
    """
    if registro["rol"] == db.ROL_SUPER and registro["usuario"] != sesion["usuario"]:
        return VETO_SUPERUSUARIO
    return None


def _objetivo(request, sesion, usuario, accion):
    """
    Busca la cuenta de destino y comprueba el blindaje.

    Devuelve (registro, None) si se puede seguir, o (None, respuesta) con el
    error ya montado. Va junto a la búsqueda y no suelto en cada ruta para que
    ninguna se lo pueda dejar.
    """
    registro = db.obtener_usuario(cfg(request).seguridad.db_path, usuario)

    if not registro:
        return None, error_htmx(request, t("No existe el usuario '%(usuario)s'",
                                           usuario=usuario))

    motivo = _veto(sesion, registro)
    if motivo:
        # Se audita porque es un intento de saltarse la jerarquía, no una
        # errata de formulario. El detalle es una etiqueta corta y es un dato:
        # se queda en español, como todos los detalles de la auditoría.
        auditar(request, sesion, accion, usuario, resultado="denegada",
                detalle="cuenta blindada")
        # En pantalla, en cambio, sale el motivo, y sale en el idioma de quien
        # lo lee: se enseña traducido desde el mismo texto.
        return None, error_htmx(request, t(motivo, usuario=usuario))

    return registro, None


@router.get("/usuarios")
def pagina_usuarios(request: Request, sesion=Depends(solo_admin)):
    return render(request, "admin_usuarios.html", {
        "exigir_totp_supervisor": db.exigir_totp_supervisor(cfg(request).seguridad.db_path),
    })


@router.get("/usuarios/tabla")
def tabla_usuarios(request: Request, sesion=Depends(solo_admin)):
    ruta = cfg(request).seguridad.db_path
    return render(request, "partials/tabla_usuarios.html", {
        "usuarios": db.listar_usuarios(ruta),
        "yo": sesion["usuario"],
        "exigir_totp_supervisor": db.exigir_totp_supervisor(ruta),
    })


@router.post("/usuarios")
def crear_usuario(
    request: Request,
    usuario: str = Form(...),
    password: str = Form(...),
    rol: str = Form(db.ROL_SUPERVISOR),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        _, concedido = db.crear_usuario(cfg(request).seguridad.db_path, usuario, password, rol)
    except ValueError as e:
        return error_htmx(request, mensaje(e))

    # Se informa del rol concedido, no del pedido: en una base vacía no son el
    # mismo. Por el panel no puede pasar —hace falta sesión— pero decir una
    # cosa distinta de la que quedó grabada es cómo se corrompe una auditoría.
    auditar(request, sesion, "crear_usuario_panel", usuario, detalle="rol=%s" % concedido)
    # El nombre del rol que se enseña es el traducido; en la auditoría queda el
    # valor, que es un dato.
    return aviso(request, t("Usuario '%(usuario)s' creado con rol %(rol)s.",
                            usuario=usuario, rol=nombre_rol(concedido)),
                 refrescar=EVENTO_REFRESCO)


@router.post("/usuarios/{usuario}/password")
def cambiar_password(
    request: Request,
    usuario: str,
    password: str = Form(...),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    ruta = cfg(request).seguridad.db_path
    registro, fallo = _objetivo(request, sesion, usuario, "cambiar_password_panel")
    if fallo:
        return fallo

    try:
        db.cambiar_password(ruta, usuario, password)
    except ValueError as e:
        return error_htmx(request, mensaje(e))

    # Cambiar la contraseña invalida las sesiones abiertas de esa cuenta
    db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "cambiar_password_panel", usuario)
    return aviso(request, t("Contraseña de '%(usuario)s' actualizada. Sus sesiones "
                            "se han cerrado.", usuario=usuario),
                 refrescar=EVENTO_REFRESCO)


@router.post("/usuarios/{usuario}/rol")
def cambiar_rol(
    request: Request,
    usuario: str,
    rol: str = Form(...),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    ruta = cfg(request).seguridad.db_path
    registro, fallo = _objetivo(request, sesion, usuario, "cambiar_rol_panel")
    if fallo:
        return fallo

    # Nadie se cambia el rol a sí mismo, superusuario incluido. Quien pudiera
    # ascenderse no tendría jerarquía por encima, y quien se degrada por error
    # se queda fuera de la página donde arreglarlo.
    if usuario == sesion["usuario"]:
        return error_htmx(request, t("No puedes cambiar tu propio rol: que lo haga "
                                     "otra cuenta"))

    # Sin cambio no hay nada que hacer, y sobre todo no hay que cerrarle la
    # sesión a nadie. Pulsar el botón sin tocar el desplegable echaba al
    # usuario del panel.
    if rol == registro["rol"]:
        return aviso(request, t("'%(usuario)s' ya tenía el rol %(rol)s: no se ha "
                                "cambiado nada.",
                                usuario=usuario, rol=nombre_rol(rol)),
                     refrescar=EVENTO_REFRESCO)

    if rol not in db.ROLES_MANDO and _ultimo_al_mando(ruta, registro):
        return error_htmx(request, t(SIN_MANDO))

    try:
        db.cambiar_rol(ruta, usuario, rol)
    except ValueError as e:
        return error_htmx(request, mensaje(e))

    db.borrar_sesiones_de(ruta, registro["id"])
    auditar(request, sesion, "cambiar_rol_panel", usuario,
            detalle="%s -> %s" % (registro["rol"], rol))
    return aviso(request, t("'%(usuario)s' ahora es %(rol)s. Deberá volver a entrar.",
                            usuario=usuario, rol=nombre_rol(rol)),
                 refrescar=EVENTO_REFRESCO)


@router.post("/usuarios/{usuario}/activo")
def activar(
    request: Request,
    usuario: str,
    activo: int = Form(...),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    ruta = cfg(request).seguridad.db_path
    registro, fallo = _objetivo(request, sesion, usuario, "activar_usuario_panel")
    if fallo:
        return fallo

    if not activo:
        if usuario == sesion["usuario"]:
            return error_htmx(request, t("No puedes desactivar tu propia cuenta"))
        if _ultimo_al_mando(ruta, registro):
            return error_htmx(request, t(SIN_MANDO))

    db.activar_usuario(ruta, usuario, bool(activo))

    if not activo:
        db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "activar_usuario_panel", usuario,
            detalle="activo=%s" % bool(activo))
    return aviso(request, t("Usuario '%(usuario)s' %(estado)s.",
                            usuario=usuario,
                            estado=t("activado") if activo else t("desactivado")),
                 refrescar=EVENTO_REFRESCO)


@router.post("/usuarios/{usuario}/borrar")
def borrar(
    request: Request,
    usuario: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    ruta = cfg(request).seguridad.db_path
    registro, fallo = _objetivo(request, sesion, usuario, "borrar_usuario_panel")
    if fallo:
        return fallo

    if usuario == sesion["usuario"]:
        return error_htmx(request, t("No puedes borrar tu propia cuenta"))

    if _ultimo_al_mando(ruta, registro):
        return error_htmx(request, t(SIN_MANDO))

    db.borrar_usuario(ruta, usuario)
    auditar(request, sesion, "borrar_usuario_panel", usuario)
    return aviso(request, t("Usuario '%(usuario)s' eliminado.", usuario=usuario),
                 refrescar=EVENTO_REFRESCO)


@router.post("/usuarios/{usuario}/totp/restablecer")
def restablecer_totp(
    request: Request,
    usuario: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Le quita el segundo factor a una cuenta que ha perdido su móvil.

    Un admin no puede activárselo a nadie —haría falta el móvil ajeno— pero sí
    quitárselo, que es la única salida cuando alguien se queda fuera. Se
    cierran además sus sesiones: si el segundo factor estaba comprometido, las
    que hubiera abiertas también lo están.

    Al superusuario no se lo quita nadie: quitarle el segundo factor es rebajar
    a una contraseña la cuenta que manda. Para eso está la CLI, que exige estar
    dentro del servidor.
    """
    ruta = cfg(request).seguridad.db_path
    registro, fallo = _objetivo(request, sesion, usuario, "totp_restablecer")
    if fallo:
        return fallo

    if not registro["totp_activado"] and not registro["totp_secret"]:
        return error_htmx(request, t("'%(usuario)s' no tiene segundo factor "
                                     "configurado", usuario=usuario))

    db.desactivar_totp(ruta, usuario)
    db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "totp_restablecer", usuario)
    return aviso(
        request,
        t("Segundo factor de '%(usuario)s' restablecido y sus sesiones cerradas. "
          "Tendrá que volver a darlo de alta.", usuario=usuario),
        refrescar=EVENTO_REFRESCO,
    )


@router.get("/politica/totp-supervisor")
def panel_politica_totp(request: Request, sesion=Depends(solo_admin)):
    return render(request, "partials/politica_totp.html", {
        "exigir_totp_supervisor": db.exigir_totp_supervisor(cfg(request).seguridad.db_path),
    })


@router.post("/politica/totp-supervisor")
def politica_totp_supervisor(
    request: Request,
    exigir: int = Form(...),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Impone (o levanta) el segundo factor para las cuentas de rol 'supervisor'.

    Vive en la base y no en config.yaml porque el panel corre como 'ovpnweb' y
    config.yaml es root:ovpnweb 0640: no puede escribirlo. Y porque es una
    decisión de operación, no de despliegue.

    No alcanza a quien manda —superusuario ni admins— a propósito: cada uno
    decide el suyo desde su perfil. Si se pudiera imponer desde aquí, un admin
    dejaría fuera a otro.
    """
    ruta = cfg(request).seguridad.db_path
    activar = bool(int(exigir))

    db.guardar_ajuste(ruta, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1" if activar else "0")
    auditar(request, sesion, "politica_totp_supervisor", db.ROL_SUPERVISOR,
            detalle="exigido" if activar else "no exigido")

    if activar:
        texto = t("Segundo factor exigido a las cuentas de rol %(rol)s. Las que no "
                  "lo tengan solo podrán ir a su perfil hasta activarlo.",
                  rol=nombre_rol(db.ROL_SUPERVISOR))
    else:
        texto = t("El segundo factor deja de ser obligatorio para el rol %(rol)s.",
                  rol=nombre_rol(db.ROL_SUPERVISOR))

    return aviso(request, texto, refrescar=EVENTO_REFRESCO)


# Las sesiones no son un filtro más sobre los sucesos: emparejan dos de ellos en
# una sola fila, así que la tabla tiene otras columnas y se atiende aparte. Se
# valida junto a los filtros —que son condiciones SQL y viven en
# db.FILTROS_EVENTOS_VPN, igual que los del panel— para que una URL escrita a
# mano no cuele.
VISTA_SESIONES = "sesiones"
VISTAS_VPN = set(db.FILTROS_EVENTOS_VPN) | {VISTA_SESIONES}


@router.get("/auditoria")
def pagina_auditoria(
    request: Request,
    fuente: str = "panel",
    filtro: str = "todo",
    pagina: int = 1,
    por_pagina: int = 50,
    sesion=Depends(usuario_actual),
):
    """
    La auditoría la puede consultar cualquier usuario autenticado.

    Dos fuentes distintas, y por eso dos pestañas y no una tabla mezclada:

    - 'panel' sale de la tabla `auditoria`, son acciones de una cuenta del
      panel y llevan usuario.
    - 'vpn' sale de la tabla `eventos_vpn`, son conexiones de un certificado y
      no tienen cuenta del panel. Las ingiere del log el vigilante; aquí no se
      abre ningún archivo.

    Las dos se filtran y se paginan en SQL, por el mismo motivo: las dos tablas
    crecen sin techo y traerlas enteras para descartar la mayor parte sería
    leerse el historial completo en cada visita.

    Dentro de 'vpn', la vista de sesiones empareja cada conexión con su
    desconexión para poder dar la duración. Esa no se pagina en SQL: emparejar
    exige un tramo contiguo, así que se trae uno acotado y se pagina ya
    emparejado. Va aquí y no en una página aparte porque es lo mismo mirado de
    otra manera, no otra fuente.
    """
    c = cfg(request)
    ruta = c.seguridad.db_path
    fuente = "vpn" if fuente == "vpn" else "panel"
    validos = VISTAS_VPN if fuente == "vpn" else db.FILTROS_AUDITORIA
    if filtro not in validos:
        filtro = "todo"

    base = "/admin/auditoria?fuente=%s&filtro=%s" % (fuente, filtro)
    # es_fallo viaja al contexto para que la etiqueta de cada fila y el filtro
    # de fallos respondan lo mismo: son la misma pregunta hecha dos veces.
    contexto = {"fuente": fuente, "filtro": filtro, "es_fallo": db.es_fallo}

    if fuente == "vpn" and filtro == VISTA_SESIONES:
        sucesos = db.listar_eventos_vpn(ruta, limite=eventos_vpn.EVENTOS_SESIONES)
        sesiones_vpn, avisos = eventos_vpn.sesiones_de(sucesos)
        pg = paginar(len(sesiones_vpn), pagina, por_pagina, base)
        contexto.update({
            "sesiones_vpn": sesiones_vpn[
                pg["desplazamiento"]:pg["desplazamiento"] + pg["por_pagina"]
            ],
            "avisos": eventos.avisos(c) + avisos,
            "pg": pg,
        })
    elif fuente == "vpn":
        total = db.contar_eventos_vpn(ruta, filtro)
        pg = paginar(total, pagina, por_pagina, base)
        contexto.update({
            "eventos": db.listar_eventos_vpn(
                ruta, pg["por_pagina"], pg["desplazamiento"], filtro
            ),
            "avisos": eventos.avisos(c),
            "pg": pg,
        })
    else:
        total = db.contar_auditoria(ruta, filtro)
        pg = paginar(total, pagina, por_pagina, base)
        contexto.update({
            "entradas": db.listar_auditoria(
                ruta, pg["por_pagina"], pg["desplazamiento"], filtro
            ),
            "pg": pg,
        })

    return render(request, "auditoria.html", contexto)
