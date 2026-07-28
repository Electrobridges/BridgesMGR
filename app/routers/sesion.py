"""
Login, segundo factor y logout.

El login tiene dos pasos cuando la cuenta usa TOTP: la contraseña deja un
permiso temporal (cookie ovpnweb_2fa, 5 minutos) y el código lo convierte en
sesión. Ese permiso no da acceso a nada por sí solo.

Los códigos fallidos cuentan para el mismo contador de bloqueo que las
contraseñas: si no, el segundo factor sería un campo de 6 dígitos con
intentos ilimitados, que se agota en unas horas.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from .. import db
from ..auth import (
    cerrar_pendiente,
    cerrar_sesion,
    comprobar_bloqueo,
    iniciar_pendiente,
    iniciar_sesion,
    ip_cliente,
    pendiente_actual,
    sesion_opcional,
    usuario_actual,
)
from ..core import totp
from .comun import auditar, cfg, render

router = APIRouter()


def _bloqueado(request, usuario, bloqueo):
    """Respuesta común cuando la clave usuario+IP está bloqueada"""
    minutos = max(1, bloqueo // 60)
    auditar(request, None, "login", usuario, "bloqueado")
    return render(
        request,
        "login.html",
        {"error": "Demasiados intentos fallidos. Prueba de nuevo en %d minuto(s)." % minutos},
        status_code=429,
    )


@router.get("/login")
def formulario_login(request: Request):
    if sesion_opcional(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": None})


@router.post("/login")
def procesar_login(
    request: Request,
    usuario: str = Form(...),
    password: str = Form(...),
):
    c = cfg(request)
    usuario = usuario.strip()

    clave, bloqueo = comprobar_bloqueo(request, usuario)
    if bloqueo:
        return _bloqueado(request, usuario, bloqueo)

    registro = db.verificar_password(c.seguridad.db_path, usuario, password)

    if not registro:
        db.registrar_fallo(
            c.seguridad.db_path,
            clave,
            c.seguridad.max_intentos_login,
            c.seguridad.bloqueo_login_min,
        )
        db.registrar(
            c.seguridad.db_path, usuario, "login", usuario, "fallo", ip=ip_cliente(request)
        )
        # Mensaje genérico a propósito: no revelamos si el usuario existe
        return render(
            request,
            "login.html",
            {"error": "Usuario o contraseña incorrectos"},
            status_code=401,
        )

    # La contraseña es correcta, pero el contador de intentos NO se limpia
    # todavía si falta el código: si no, un atacante con la contraseña tendría
    # intentos infinitos contra los 6 dígitos.
    if registro["totp_activado"]:
        respuesta = render(request, "login_totp.html", {"error": None, "usuario": usuario})
        iniciar_pendiente(request, respuesta, registro)
        db.registrar(
            c.seguridad.db_path, usuario, "login", usuario, "2fa_pendiente",
            ip=ip_cliente(request),
        )
        return respuesta

    db.limpiar_intentos(c.seguridad.db_path, clave)

    respuesta = RedirectResponse("/", status_code=303)
    iniciar_sesion(request, respuesta, registro)
    db.registrar(
        c.seguridad.db_path, usuario, "login", usuario, "ok", ip=ip_cliente(request)
    )

    return respuesta


@router.get("/login/codigo")
def formulario_codigo(request: Request):
    """Por si se recarga la página del segundo paso"""
    pendiente = pendiente_actual(request)
    if not pendiente:
        return RedirectResponse("/login", status_code=303)

    return render(
        request, "login_totp.html", {"error": None, "usuario": pendiente["usuario"]}
    )


@router.post("/login/codigo")
def verificar_codigo(request: Request, codigo: str = Form(...)):
    c = cfg(request)
    pendiente = pendiente_actual(request)

    if not pendiente:
        # Caducó el permiso temporal o nunca lo hubo: se vuelve a empezar
        respuesta = render(
            request,
            "login.html",
            {"error": "La verificación ha caducado. Entra otra vez."},
            status_code=401,
        )
        respuesta.delete_cookie("ovpnweb_2fa", path="/")
        return respuesta

    usuario = pendiente["usuario"]
    clave, bloqueo = comprobar_bloqueo(request, usuario)
    if bloqueo:
        respuesta = _bloqueado(request, usuario, bloqueo)
        cerrar_pendiente(request, respuesta)
        return respuesta

    paso = totp.verificar(
        pendiente["totp_secret"], codigo, paso_minimo=pendiente["totp_ultimo_paso"]
    )

    if paso is None:
        db.registrar_fallo(
            c.seguridad.db_path,
            clave,
            c.seguridad.max_intentos_login,
            c.seguridad.bloqueo_login_min,
        )
        db.registrar(
            c.seguridad.db_path, usuario, "login", usuario, "2fa_fallo",
            ip=ip_cliente(request),
        )
        return render(
            request,
            "login_totp.html",
            {"error": "Código incorrecto o caducado", "usuario": usuario},
            status_code=401,
        )

    # Se anota el paso consumido para que ese mismo código no valga otra vez
    db.registrar_paso_totp(c.seguridad.db_path, pendiente["id"], paso)
    db.limpiar_intentos(c.seguridad.db_path, clave)

    respuesta = RedirectResponse("/", status_code=303)
    cerrar_pendiente(request, respuesta)
    iniciar_sesion(request, respuesta, pendiente)
    db.registrar(
        c.seguridad.db_path, usuario, "login", usuario, "ok", detalle="con segundo factor",
        ip=ip_cliente(request),
    )

    return respuesta


@router.post("/logout")
def logout(request: Request, sesion=Depends(usuario_actual)):
    respuesta = RedirectResponse("/login", status_code=303)
    auditar(request, sesion, "logout", sesion["usuario"])
    cerrar_sesion(request, respuesta)
    return respuesta
