"""
Endurecimiento del servidor VPN: auditoría del server.conf.

solo_admin, igual que Configuración: el informe es un mapa de los puntos
débiles del servidor, justo lo que no se le enseña a quien solo consulta.
"""

from fastapi import APIRouter, Depends, Request

from ..auth import solo_admin
from ..core import auditor, easyrsa, salud
from .comun import cfg, render

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
