"""
Perfil de la cuenta: alta y baja del segundo factor.

Cada uno gestiona el suyo. Un administrador no puede activarle el TOTP a
otro —haría falta su móvil— pero sí puede restablecerlo desde
/admin/usuarios cuando alguien pierde el suyo.

El alta es en dos tiempos: se genera el secreto y no se da por bueno hasta que
el usuario teclea un código correcto. Así nadie se queda fuera por haberlo
copiado mal en la aplicación del móvil.
"""

from fastapi import APIRouter, Depends, Form, Request

from .. import db, qr
from ..auth import usuario_actual, verificar_csrf
from ..core import totp
from .comun import cfg, render

router = APIRouter(prefix="/perfil")

EMISOR = "OpenVPN Manager"


def _estado(request, sesion, secreto_pendiente=None, mensaje=None, error=None):
    """Contexto del panel de segundo factor para la plantilla"""
    ruta = cfg(request).seguridad.db_path
    registro = db.obtener_usuario(ruta, sesion["usuario"])

    # El secreto solo se enseña durante el alta, nunca al volver a la página:
    # una vez guardado en el móvil no hay motivo para volver a mostrarlo. El
    # QR corre la misma suerte, porque es el secreto en otro formato.
    secreto = secreto_pendiente
    uri = totp.uri_otpauth(secreto, registro["usuario"], EMISOR) if secreto else None

    imagen_qr, fallo_qr = None, None
    if uri:
        try:
            imagen_qr = qr.data_uri(uri)
        except qr.QRNoDisponible as e:
            # Nada de huecos mudos: si no hay QR se dice por qué, y el alta
            # sigue siendo posible tecleando la clave.
            fallo_qr = str(e)

    return {
        "activado": bool(registro["totp_activado"]),
        "obligatorio": db.totp_obligatorio(ruta, registro["rol"]),
        "secreto": secreto,
        "secreto_legible": totp.formatear_secreto(secreto) if secreto else None,
        "uri": uri,
        "qr": imagen_qr,
        "fallo_qr": fallo_qr,
        "mensaje": mensaje,
        "error": error,
    }


def _panel(request, sesion, **kwargs):
    return render(request, "partials/totp_panel.html", _estado(request, sesion, **kwargs))


@router.get("")
def pagina_perfil(request: Request, sesion=Depends(usuario_actual)):
    return render(request, "perfil.html", _estado(request, sesion))


@router.get("/totp")
def panel_totp(request: Request, sesion=Depends(usuario_actual)):
    return _panel(request, sesion)


@router.post("/totp/iniciar")
def iniciar_alta(request: Request, sesion=Depends(verificar_csrf)):
    ruta = cfg(request).seguridad.db_path
    registro = db.obtener_usuario(ruta, sesion["usuario"])

    if registro["totp_activado"]:
        return _panel(request, sesion,
                      error="El segundo factor ya está activo en esta cuenta.")

    secreto = totp.generar_secreto()
    db.guardar_secreto_totp(ruta, sesion["usuario"], secreto)

    db.registrar(ruta, sesion["usuario"], "totp_alta", sesion["usuario"], "iniciada",
                 ip=request.client.host if request.client else None)

    return _panel(request, sesion, secreto_pendiente=secreto)


@router.post("/totp/confirmar")
def confirmar_alta(
    request: Request,
    codigo: str = Form(...),
    sesion=Depends(verificar_csrf),
):
    ruta = cfg(request).seguridad.db_path
    registro = db.obtener_usuario(ruta, sesion["usuario"])
    ip = request.client.host if request.client else None

    if not registro["totp_secret"]:
        return _panel(request, sesion,
                      error="No hay ningún alta en curso. Empieza de nuevo.")

    paso = totp.verificar(
        registro["totp_secret"], codigo, paso_minimo=registro["totp_ultimo_paso"]
    )

    if paso is None:
        db.registrar(ruta, sesion["usuario"], "totp_alta", sesion["usuario"], "fallo",
                     detalle="código incorrecto", ip=ip)
        # Se mantiene el mismo secreto: el usuario ya lo tiene en el móvil y
        # cambiarlo aquí le obligaría a volver a darlo de alta.
        return _panel(
            request, sesion,
            secreto_pendiente=registro["totp_secret"],
            error="Código incorrecto. Comprueba la hora del móvil e inténtalo otra vez.",
        )

    db.activar_totp(ruta, sesion["usuario"], paso)
    db.registrar(ruta, sesion["usuario"], "totp_alta", sesion["usuario"], "ok", ip=ip)

    return _panel(
        request, sesion,
        mensaje="Segundo factor activado. A partir de ahora se te pedirá el código al entrar.",
    )


@router.post("/totp/desactivar")
def desactivar(request: Request, sesion=Depends(verificar_csrf)):
    ruta = cfg(request).seguridad.db_path
    ip = request.client.host if request.client else None

    if db.totp_obligatorio(ruta, sesion["rol"]):
        db.registrar(ruta, sesion["usuario"], "totp_baja", sesion["usuario"], "denegada",
                     detalle="la política lo exige para este rol", ip=ip)
        return _panel(
            request, sesion,
            error="Un administrador ha impuesto el segundo factor para tu rol: "
                  "no puedes desactivarlo.",
        )

    db.desactivar_totp(ruta, sesion["usuario"])
    db.registrar(ruta, sesion["usuario"], "totp_baja", sesion["usuario"], "ok", ip=ip)

    return _panel(request, sesion, mensaje="Segundo factor desactivado.")
