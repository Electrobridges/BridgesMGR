"""
Login, segundo factor y logout.

El login tiene dos pasos cuando la cuenta usa TOTP: la contraseña deja un
permiso temporal (cookie ovpnweb_2fa, 5 minutos) y el código lo convierte en
sesión. Ese permiso no da acceso a nada por sí solo.

Los códigos fallidos cuentan para el mismo contador de bloqueo que las
contraseñas: si no, el segundo factor sería un campo de 6 dígitos con
intentos ilimitados, que se agota en unas horas.

Todo lo que pasa aquí se anota con auditar() y nunca con db.registrar(): la
política de avisos cuelga de auditar(), y un intento fallido es la primera
señal de que alguien está probando contraseñas contra el panel.
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
    pendiente_actual,
    sesion_opcional,
    usuario_actual,
)
from ..core import totp
from .comun import auditar, cfg, render

router = APIRouter()


def _auditar_login(request, usuario, resultado, detalle=None):
    """
    Un suceso de login, con la cuenta en las dos columnas.

    Todavía no hay sesión —de eso va la petición—, así que la cuenta se pasa
    como 'actor' para que la auditoría no la deje vacía. Va como objetivo
    además porque en un login quien actúa y a quién afecta son el mismo.
    """
    auditar(request, None, "login", usuario, resultado, detalle, actor=usuario)


def _bloqueado(request, usuario, bloqueo):
    """Respuesta común cuando la clave usuario+IP está bloqueada"""
    minutos = max(1, bloqueo // 60)
    _auditar_login(request, usuario, "bloqueado")
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
        _auditar_login(request, usuario, "fallo")
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
        # El resultado es 'ok' porque describe el paso que acaba de terminar
        # —la contraseña— y no el login entero, que aún no ha pasado. Con un
        # 'pendiente' aquí, cada login correcto acababa en la pestaña de
        # fallos, que selecciona por resultado != 'ok'. La fila se queda porque
        # una así SIN la de después es el rastro de una contraseña acertada que
        # nunca completó el segundo factor.
        _auditar_login(request, usuario, "ok",
                       "contraseña correcta, falta el segundo factor")
        return respuesta

    db.limpiar_intentos(c.seguridad.db_path, clave)

    respuesta = RedirectResponse("/", status_code=303)
    iniciar_sesion(request, respuesta, registro)
    _auditar_login(request, usuario, "ok")

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
        _auditar_login(request, usuario, "2fa_fallo")
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
    _auditar_login(request, usuario, "ok", "con segundo factor")

    return respuesta


@router.post("/logout")
def logout(request: Request, sesion=Depends(usuario_actual)):
    respuesta = RedirectResponse("/login", status_code=303)
    auditar(request, sesion, "logout", sesion["usuario"])
    cerrar_sesion(request, respuesta)
    return respuesta
