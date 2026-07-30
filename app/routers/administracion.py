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

from .. import db
from ..auth import solo_admin, usuario_actual, verificar_csrf
from ..core import eventos_vpn
from .comun import auditar, aviso, cfg, error_htmx, render

router = APIRouter(prefix="/admin")

EVENTO_REFRESCO = "usuarios-actualizados"

SIN_MANDO = "No puedes dejar el panel sin ninguna cuenta capaz de administrarlo"


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
    """
    if registro["rol"] == db.ROL_SUPER and registro["usuario"] != sesion["usuario"]:
        return ("'%s' es el superusuario: solo esa cuenta puede administrarse a "
                "sí misma. Desde el servidor queda la CLI." % registro["usuario"])
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
        return None, error_htmx(request, "No existe el usuario '%s'" % usuario)

    motivo = _veto(sesion, registro)
    if motivo:
        # Se audita porque es un intento de saltarse la jerarquía, no una
        # errata de formulario.
        auditar(request, sesion, accion, usuario, resultado="denegada",
                detalle="cuenta blindada")
        return None, error_htmx(request, motivo)

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
        return error_htmx(request, str(e))

    # Se informa del rol concedido, no del pedido: en una base vacía no son el
    # mismo. Por el panel no puede pasar —hace falta sesión— pero decir una
    # cosa distinta de la que quedó grabada es cómo se corrompe una auditoría.
    auditar(request, sesion, "crear_usuario_panel", usuario, detalle="rol=%s" % concedido)
    return aviso(request, "Usuario '%s' creado con rol %s." % (usuario, concedido),
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
        return error_htmx(request, str(e))

    # Cambiar la contraseña invalida las sesiones abiertas de esa cuenta
    db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "cambiar_password_panel", usuario)
    return aviso(request, "Contraseña de '%s' actualizada. Sus sesiones se han cerrado." % usuario,
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
        return error_htmx(request, "No puedes cambiar tu propio rol: que lo haga otra cuenta")

    # Sin cambio no hay nada que hacer, y sobre todo no hay que cerrarle la
    # sesión a nadie. Pulsar el botón sin tocar el desplegable echaba al
    # usuario del panel.
    if rol == registro["rol"]:
        return aviso(request, "'%s' ya tenía el rol %s: no se ha cambiado nada." % (usuario, rol),
                     refrescar=EVENTO_REFRESCO)

    if rol not in db.ROLES_MANDO and _ultimo_al_mando(ruta, registro):
        return error_htmx(request, SIN_MANDO)

    try:
        db.cambiar_rol(ruta, usuario, rol)
    except ValueError as e:
        return error_htmx(request, str(e))

    db.borrar_sesiones_de(ruta, registro["id"])
    auditar(request, sesion, "cambiar_rol_panel", usuario,
            detalle="%s -> %s" % (registro["rol"], rol))
    return aviso(request, "'%s' ahora es %s. Deberá volver a entrar." % (usuario, rol),
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
            return error_htmx(request, "No puedes desactivar tu propia cuenta")
        if _ultimo_al_mando(ruta, registro):
            return error_htmx(request, SIN_MANDO)

    db.activar_usuario(ruta, usuario, bool(activo))

    if not activo:
        db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "activar_usuario_panel", usuario,
            detalle="activo=%s" % bool(activo))
    return aviso(request, "Usuario '%s' %s." % (usuario, "activado" if activo else "desactivado"),
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
        return error_htmx(request, "No puedes borrar tu propia cuenta")

    if _ultimo_al_mando(ruta, registro):
        return error_htmx(request, SIN_MANDO)

    db.borrar_usuario(ruta, usuario)
    auditar(request, sesion, "borrar_usuario_panel", usuario)
    return aviso(request, "Usuario '%s' eliminado." % usuario, refrescar=EVENTO_REFRESCO)


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
        return error_htmx(request, "'%s' no tiene segundo factor configurado" % usuario)

    db.desactivar_totp(ruta, usuario)
    db.borrar_sesiones_de(ruta, registro["id"])

    auditar(request, sesion, "totp_restablecer", usuario)
    return aviso(
        request,
        "Segundo factor de '%s' restablecido y sus sesiones cerradas. "
        "Tendrá que volver a darlo de alta." % usuario,
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
        mensaje = ("Segundo factor exigido a las cuentas de rol supervisor. "
                   "Las que no lo tengan solo podrán ir a su perfil hasta activarlo.")
    else:
        mensaje = "El segundo factor deja de ser obligatorio para el rol supervisor."

    return aviso(request, mensaje, refrescar=EVENTO_REFRESCO)


@router.get("/auditoria")
def pagina_auditoria(
    request: Request,
    fuente: str = "panel",
    filtro: str = "todo",
    sesion=Depends(usuario_actual),
):
    """
    La auditoría la puede consultar cualquier usuario autenticado.

    Dos fuentes distintas, y por eso dos pestañas y no una tabla mezclada:

    - 'panel' sale de la tabla `auditoria`, son acciones de una cuenta del
      panel y llevan usuario.
    - 'vpn' sale del log de OpenVPN, son conexiones de un certificado y no
      tienen cuenta del panel. Se leen en vivo; no se guardan en la base.
    """
    c = cfg(request)
    contexto = {"fuente": "vpn" if fuente == "vpn" else "panel", "filtro": filtro}

    if contexto["fuente"] == "vpn":
        eventos, avisos = eventos_vpn.leer_eventos(c)
        if filtro == "fallos":
            eventos = [e for e in eventos if e["fallo"]]
        elif filtro == "conexiones":
            eventos = [e for e in eventos if e["tipo"] == eventos_vpn.CONEXION]
        contexto.update({"eventos": eventos, "avisos": avisos})
    else:
        contexto["entradas"] = db.listar_auditoria(c.seguridad.db_path, 200)

    return render(request, "auditoria.html", contexto)
