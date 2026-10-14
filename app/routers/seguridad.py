"""
Endurecimiento del servidor VPN: auditoría del server.conf y bloqueo de IPs.

solo_admin, igual que Configuración: el informe es un mapa de los puntos
débiles del servidor, justo lo que no se le enseña a quien solo consulta.
"""

import ipaddress

from fastapi import APIRouter, Depends, Form, Request

from .. import bloqueos, db
from ..auth import ip_cliente, solo_admin, verificar_csrf
from ..core import auditor, easyrsa, salud
from .comun import auditar, aviso, cfg, error_htmx, render

EVENTO_BLOQUEOS = "bloqueos-actualizados"

router = APIRouter(prefix="/seguridad")


def _crl_dias(c):
    crl = "%s/pki/crl.pem" % c.openvpn.easyrsa_path.rstrip("/")
    try:
        return salud.caducidad_crl(crl)[1]
    except salud.SinCRL:
        return None


@router.get("")
def pagina_seguridad(request: Request, sesion=Depends(solo_admin)):
    c = cfg(request)
    error = None
    informe = None
    ruta = None

    try:
        datos = easyrsa.server_conf(c)
    except easyrsa.ErrorHelper as e:
        error = "No se pudo leer el server.conf: %s" % e
    else:
        ruta = datos.get("ruta")
        informe = auditor.auditar(datos.get("directivas", []), datos.get("version", ""),
                                  _crl_dias(c))
        informe["version"] = datos.get("version", "")

    return render(request, "seguridad.html", {
        "bloqueo": bloqueos.ajustes(c.seguridad.db_path),
        "informe": informe,
        "error": error,
        "ruta": ruta,
        "niveles": {
            auditor.CRITICO: ("crítico", "mal"),
            auditor.AVISO: ("aviso", "aviso"),
            auditor.SUGERENCIA: ("sugerencia", "info"),
            auditor.BIEN: ("bien", "ok"),
        },
    })


# ------------------------------------------------------- bloqueo de IPs

@router.get("/bloqueos/tabla")
def tabla_bloqueos(request: Request, sesion=Depends(solo_admin)):
    c = cfg(request)
    ruta = c.seguridad.db_path
    error = None
    en_cortafuegos = None
    try:
        estado = easyrsa.listar_bloqueos(c)
        if estado.get("nft"):
            en_cortafuegos = {b["ip"]: b["expira_s"] for b in estado.get("bloqueadas", [])}
        else:
            error = "nftables no está instalado: no se puede bloquear nada (apt install nftables)."
    except easyrsa.ErrorHelper as e:
        error = "No se pudo consultar el cortafuegos: %s" % e

    return render(request, "partials/tabla_bloqueos.html", {
        "activos": db.bloqueos_activos(ruta),
        "historial": db.historial_bloqueos(ruta, 20),
        "en_cortafuegos": en_cortafuegos,
        "error": error,
    })


@router.post("/bloqueos/ajustes")
def ajustar_bloqueo(
    request: Request,
    activo: str = Form(None),
    umbral: str = Form("10"),
    ventana_min: str = Form("10"),
    duracion_min: str = Form("60"),
    lista_blanca: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        a = bloqueos.guardar_ajustes(cfg(request).seguridad.db_path, bool(activo),
                                     umbral, ventana_min, duracion_min, lista_blanca)
    except bloqueos.AjusteInvalido as e:
        return error_htmx(request, str(e))

    detalle = ("activo: %d intentos en %d min -> %d min; lista blanca: %s"
               % (a["umbral"], a["ventana_min"], a["duracion_min"],
                  ", ".join(a["lista_blanca"]) or "vacía")) if a["activo"] else "desactivado"
    auditar(request, sesion, "ajustar_bloqueo", None, detalle=detalle)
    return aviso(request, "Bloqueo automático %s." % ("activado" if a["activo"] else "desactivado"),
                 refrescar=EVENTO_BLOQUEOS)


@router.post("/bloqueos")
def bloquear_ip(
    request: Request,
    ip: str = Form(...),
    minutos: str = Form("60"),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        direccion = str(ipaddress.IPv4Address(ip.strip()))
        duracion = int(minutos)
        if not 1 <= duracion <= bloqueos.MAX_DURACION_MIN:
            raise ValueError
    except ValueError:
        return error_htmx(request, "Escribe una IPv4 y una duración en minutos válidas")

    # Cortarse a uno mismo el acceso al panel es el error más fácil de cometer
    # aquí, y el único que no se puede deshacer desde el propio panel.
    if direccion == ip_cliente(request):
        return error_htmx(request, "Esa es tu propia IP: te quedarías fuera del panel.")

    try:
        bloqueos.bloquear(cfg(request), direccion, duracion, sesion["usuario"])
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "bloquear_ip", direccion, "error", str(e))
        return error_htmx(request, "No se pudo bloquear %s: %s" % (direccion, e))

    auditar(request, sesion, "bloquear_ip", direccion, detalle="a mano, %d min" % duracion)
    return aviso(request, "%s bloqueada %d minutos." % (direccion, duracion),
                 refrescar=EVENTO_BLOQUEOS)


@router.post("/bloqueos/{ip}/levantar")
def desbloquear_ip(
    request: Request,
    ip: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        direccion = bloqueos.desbloquear(cfg(request), ip)
    except ValueError:
        return error_htmx(request, "IP no válida")
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "desbloquear_ip", ip, "error", str(e))
        return error_htmx(request, "No se pudo desbloquear %s: %s" % (ip, e))

    auditar(request, sesion, "desbloquear_ip", direccion)
    return aviso(request, "%s desbloqueada." % direccion, refrescar=EVENTO_BLOQUEOS)
