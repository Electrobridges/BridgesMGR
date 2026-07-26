"""
Administración del propio panel: usuarios con acceso y registro de auditoría.

Ojo con la diferencia: aquí se gestionan las cuentas que entran al PANEL, no
los clientes VPN. Esos están en routers/clientes.py.
"""

from fastapi import APIRouter, Depends, Form, Request

from .. import db
from ..auth import solo_admin, usuario_actual, verificar_csrf
from .comun import auditar, aviso, cfg, error_htmx, render

router = APIRouter(prefix="/admin")

EVENTO_REFRESCO = "usuarios-actualizados"


@router.get("/usuarios")
def pagina_usuarios(request: Request, sesion=Depends(solo_admin)):
    return render(request, "admin_usuarios.html", {})


@router.get("/usuarios/tabla")
def tabla_usuarios(request: Request, sesion=Depends(solo_admin)):
    return render(request, "partials/tabla_usuarios.html", {
        "usuarios": db.listar_usuarios(cfg(request).seguridad.db_path),
        "yo": sesion["usuario"],
    })


@router.post("/usuarios")
def crear_usuario(
    request: Request,
    usuario: str = Form(...),
    password: str = Form(...),
    rol: str = Form("lector"),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        db.crear_usuario(cfg(request).seguridad.db_path, usuario, password, rol)
    except ValueError as e:
        return error_htmx(request, str(e))

    auditar(request, sesion, "crear_usuario_panel", usuario, detalle="rol=%s" % rol)
    return aviso(request, "Usuario '%s' creado con rol %s." % (usuario, rol),
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

    try:
        db.cambiar_password(ruta, usuario, password)
    except ValueError as e:
        return error_htmx(request, str(e))

    # Cambiar la contraseña invalida las sesiones abiertas de esa cuenta
    registro = db.obtener_usuario(ruta, usuario)
    if registro:
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
    registro = db.obtener_usuario(ruta, usuario)

    if not registro:
        return error_htmx(request, "No existe el usuario '%s'" % usuario)

    # No dejar el panel sin ningún administrador
    if registro["rol"] == "admin" and rol != "admin" and db.contar_admins_activos(ruta) <= 1:
        return error_htmx(request, "No puedes quitar el último administrador activo")

    try:
        db.cambiar_rol(ruta, usuario, rol)
    except ValueError as e:
        return error_htmx(request, str(e))

    db.borrar_sesiones_de(ruta, registro["id"])
    auditar(request, sesion, "cambiar_rol_panel", usuario, detalle="rol=%s" % rol)
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
    registro = db.obtener_usuario(ruta, usuario)

    if not registro:
        return error_htmx(request, "No existe el usuario '%s'" % usuario)

    if not activo:
        if usuario == sesion["usuario"]:
            return error_htmx(request, "No puedes desactivar tu propia cuenta")
        if registro["rol"] == "admin" and db.contar_admins_activos(ruta) <= 1:
            return error_htmx(request, "No puedes desactivar el último administrador activo")

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
    registro = db.obtener_usuario(ruta, usuario)

    if not registro:
        return error_htmx(request, "No existe el usuario '%s'" % usuario)

    if usuario == sesion["usuario"]:
        return error_htmx(request, "No puedes borrar tu propia cuenta")

    if registro["rol"] == "admin" and db.contar_admins_activos(ruta) <= 1:
        return error_htmx(request, "No puedes borrar el último administrador activo")

    db.borrar_usuario(ruta, usuario)
    auditar(request, sesion, "borrar_usuario_panel", usuario)
    return aviso(request, "Usuario '%s' eliminado." % usuario, refrescar=EVENTO_REFRESCO)


@router.get("/auditoria")
def pagina_auditoria(request: Request, sesion=Depends(usuario_actual)):
    """La auditoría la puede consultar cualquier usuario autenticado"""
    return render(request, "auditoria.html", {
        "entradas": db.listar_auditoria(cfg(request).seguridad.db_path, 200),
    })
