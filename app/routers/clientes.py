"""
Gestión de clientes VPN: alta, revocación, restauración, expulsión y descarga
del .ovpn.

Todas las mutaciones exigen rol admin y cabecera CSRF, y quedan registradas en
la auditoría con su resultado.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from ..auth import solo_admin, usuario_actual, verificar_csrf
from ..core import easyrsa
from ..core.conexiones import obtener_conexiones
from ..core.mgmt import ErrorManagement, desconectar_cliente
from ..core.validacion import CNInvalido, validar_cn
from .comun import auditar, aviso, cfg, error_htmx, render

router = APIRouter(prefix="/clientes")

EVENTO_REFRESCO = "clientes-actualizados"


def _estado_clientes(request):
    """Une la lista de certificados con quién está conectado ahora mismo"""
    c = cfg(request)
    errores = []

    try:
        certificados = easyrsa.listar_certificados(c)
    except easyrsa.ErrorHelper as e:
        certificados = {"validos": [], "revocados": []}
        errores.append("No se pudo consultar la PKI: %s" % e)

    conexiones, _fuente, errores_con = obtener_conexiones(c)
    errores += errores_con
    conectados = {con["user"] for con in conexiones}

    filas = []
    for cn in certificados["validos"]:
        filas.append({"cn": cn, "estado": "valido", "conectado": cn in conectados})
    for cn in certificados["revocados"]:
        filas.append({"cn": cn, "estado": "revocado", "conectado": False})

    filas.sort(key=lambda f: (f["estado"] != "valido", f["cn"].lower()))
    return filas, errores


@router.get("")
def pagina_clientes(request: Request, sesion=Depends(usuario_actual)):
    return render(request, "clientes.html", {"es_admin": sesion["rol"] == "admin"})


@router.get("/tabla")
def tabla_clientes(request: Request, sesion=Depends(usuario_actual)):
    filas, errores = _estado_clientes(request)
    return render(request, "partials/tabla_clientes.html", {
        "filas": filas,
        "errores": errores,
        "es_admin": sesion["rol"] == "admin",
    })


@router.post("")
def crear_cliente(
    request: Request,
    cn: str = Form(...),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        easyrsa.crear_cliente(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "crear_cliente", cn, "error", str(e))
        return error_htmx(request, "No se pudo crear '%s': %s" % (cn, e))

    auditar(request, sesion, "crear_cliente", cn)
    return aviso(
        request,
        "Cliente '%s' creado. Ya puedes descargar su archivo .ovpn." % cn,
        refrescar=EVENTO_REFRESCO,
    )


@router.post("/{cn}/revocar")
def revocar_cliente(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        easyrsa.revocar(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "revocar", cn, "error", str(e))
        return error_htmx(request, "No se pudo revocar '%s': %s" % (cn, e))

    auditar(request, sesion, "revocar", cn)
    return aviso(
        request,
        "Acceso de '%s' revocado y CRL regenerada. Reinicia %s para aplicarlo."
        % (cn, cfg(request).openvpn.servicio),
        tipo="aviso",
        refrescar=EVENTO_REFRESCO,
    )


@router.post("/{cn}/restaurar")
def restaurar_cliente(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        easyrsa.restaurar(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "restaurar", cn, "error", str(e))
        return error_htmx(request, "No se pudo restaurar '%s': %s" % (cn, e))

    auditar(request, sesion, "restaurar", cn)
    return aviso(
        request,
        "Certificado de '%s' reemitido. Descarga el nuevo .ovpn: el anterior ya no sirve." % cn,
        refrescar=EVENTO_REFRESCO,
    )


@router.post("/{cn}/desconectar")
def desconectar(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    c = cfg(request)

    try:
        desconectar_cliente(c.openvpn.mgmt_host, c.openvpn.mgmt_port, cn)
    except ErrorManagement as e:
        auditar(request, sesion, "desconectar", cn, "error", str(e))
        return error_htmx(request, "No se pudo desconectar a '%s': %s" % (cn, e))

    auditar(request, sesion, "desconectar", cn)
    return aviso(request, "'%s' desconectado." % cn, refrescar=EVENTO_REFRESCO)


@router.get("/{cn}/ovpn")
def descargar_ovpn(request: Request, cn: str, sesion=Depends(solo_admin)):
    """
    Descarga el perfil .ovpn con la clave privada embebida.

    Solo admin: este archivo ES el acceso a la VPN. Queda auditado.
    """
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        contenido = easyrsa.generar_ovpn(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "descargar_ovpn", cn, "error", str(e))
        return error_htmx(request, "No se pudo generar el perfil de '%s': %s" % (cn, e))

    auditar(request, sesion, "descargar_ovpn", cn)

    return Response(
        content=contenido,
        media_type="application/x-openvpn-profile",
        headers={
            "Content-Disposition": 'attachment; filename="%s.ovpn"' % cn,
            "Cache-Control": "no-store",
        },
    )
