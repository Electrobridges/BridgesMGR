"""Login y logout"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from .. import db
from ..auth import (
    cerrar_sesion,
    comprobar_bloqueo,
    iniciar_sesion,
    ip_cliente,
    sesion_opcional,
    usuario_actual,
)
from .comun import auditar, cfg, render

router = APIRouter()


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
        minutos = max(1, bloqueo // 60)
        auditar(request, None, "login", usuario, "bloqueado")
        return render(
            request,
            "login.html",
            {"error": "Demasiados intentos fallidos. Prueba de nuevo en %d minuto(s)." % minutos},
            status_code=429,
        )

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

    db.limpiar_intentos(c.seguridad.db_path, clave)

    respuesta = RedirectResponse("/", status_code=303)
    iniciar_sesion(request, respuesta, registro)
    db.registrar(
        c.seguridad.db_path, usuario, "login", usuario, "ok", ip=ip_cliente(request)
    )

    return respuesta


@router.post("/logout")
def logout(request: Request, sesion=Depends(usuario_actual)):
    respuesta = RedirectResponse("/login", status_code=303)
    auditar(request, sesion, "logout", sesion["usuario"])
    cerrar_sesion(request, respuesta)
    return respuesta
