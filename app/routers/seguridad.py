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
from ..idiomas import mensaje, t
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
        error = t("No se pudo leer el server.conf: %(error)s", error=mensaje(e))
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
        # El primer elemento de cada par es el texto que se enseña y el
        # segundo es la clase de CSS: uno se traduce y el otro no.
        "niveles": {
            auditor.CRITICO: (t("crítico"), "mal"),
            auditor.AVISO: (t("aviso"), "aviso"),
            auditor.SUGERENCIA: (t("sugerencia"), "info"),
            auditor.BIEN: (t("bien"), "ok"),
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
            error = t("nftables no está instalado: no se puede bloquear nada "
                      "(apt install nftables).")
    except easyrsa.ErrorHelper as e:
        error = t("No se pudo consultar el cortafuegos: %(error)s", error=mensaje(e))

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
        # str(e) es el mensaje en español y va a los logs; mensaje(e) es el
        # mismo mensaje en el idioma de quien lo va a leer.
        return error_htmx(request, mensaje(e))

    # El detalle es un dato y se queda en español, como todos los detalles de
    # la auditoría.
    detalle = ("activo: %d intentos en %d min -> %d min; lista blanca: %s"
               % (a["umbral"], a["ventana_min"], a["duracion_min"],
                  ", ".join(a["lista_blanca"]) or "vacía")) if a["activo"] else "desactivado"
    auditar(request, sesion, "ajustar_bloqueo", None, detalle=detalle)
    return aviso(request, t("Bloqueo automático %(estado)s.",
                             estado=t("activado") if a["activo"] else t("desactivado")),
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
        return error_htmx(request, t("Escribe una IPv4 y una duración en minutos válidas"))

    # Cortarse a uno mismo el acceso al panel es el error más fácil de cometer
    # aquí, y el único que no se puede deshacer desde el propio panel.
    if direccion == ip_cliente(request):
        return error_htmx(request, t("Esa es tu propia IP: te quedarías fuera del panel."))

    try:
        bloqueos.bloquear(cfg(request), direccion, duracion, sesion["usuario"])
    except easyrsa.ErrorHelper as e:
        # A la auditoría va el mensaje en español —str(e)—: es un dato. En
        # pantalla sale el mismo mensaje, en el idioma de quien lo lee.
        auditar(request, sesion, "bloquear_ip", direccion, "error", str(e))
        return error_htmx(request, t("No se pudo bloquear %(ip)s: %(error)s",
                                     ip=direccion, error=mensaje(e)))

    auditar(request, sesion, "bloquear_ip", direccion, detalle="a mano, %d min" % duracion)
    return aviso(request, t("%(ip)s bloqueada %(minutos)s minutos.",
                             ip=direccion, minutos=duracion),
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
    except easyrsa.ErrorHelper as e:
        # ErrorHelper es un ValueError —hereda de MensajeError—, así que este
        # 'except' tiene que ir antes que el del ValueError de la IP: si no,
        # un fallo del helper salía como si la IP no valiera.
        auditar(request, sesion, "desbloquear_ip", ip, "error", str(e))
        return error_htmx(request, t("No se pudo desbloquear %(ip)s: %(error)s",
                                     ip=ip, error=mensaje(e)))
    except ValueError:
        return error_htmx(request, t("IP no válida"))

    auditar(request, sesion, "desbloquear_ip", direccion)
    return aviso(request, t("%(ip)s desbloqueada.", ip=direccion),
                 refrescar=EVENTO_BLOQUEOS)
