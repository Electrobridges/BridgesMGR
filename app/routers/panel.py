"""Dashboard, conexiones activas, logs y configuración"""

from fastapi import APIRouter, Depends, Query, Request

from ..auth import usuario_actual
from ..core import logs as core_logs
from ..core.conexiones import obtener_conexiones, resumen_trafico, top_por_trafico
from ..core.easyrsa import ErrorHelper, estado_servicio, listar_certificados
from .comun import cfg, render

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
def pagina_configuracion(request: Request, sesion=Depends(usuario_actual)):
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
    })
