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
    # Sin 'es_admin': render() ya inyecta 'manda' desde db.ROLES_MANDO. Aquí se
    # comparaba con la cadena 'admin' y al superusuario le desaparecían el
    # formulario de crear y los botones de la tabla.
    return render(request, "clientes.html")


@router.get("/tabla")
def tabla_clientes(request: Request, sesion=Depends(usuario_actual)):
    filas, errores = _estado_clientes(request)
    return render(request, "partials/tabla_clientes.html", {
        "filas": filas,
        "errores": errores,
    })


def _clave_pedida(con_clave, clave, clave2):
    """
    Devuelve la contraseña con la que cifrar la clave privada, o None.

    Aquí y no en core/easyrsa.py: esto valida lo que teclea una persona y el
    mensaje va a su pantalla. La comprobación de easyrsa.py se queda como
    última barrera, y el helper la repite por su cuenta porque desde el otro
    lado de la frontera el panel no es de fiar.

    La contraseña no se registra en ninguna parte: ni en la auditoría, ni en un
    mensaje de error, ni en el log. Solo consta que se pidió.
    """
    if not con_clave:
        return None

    if not clave:
        raise ValueError("Marcaste cifrar la clave privada pero no escribiste ninguna contraseña")
    if clave != clave2:
        raise ValueError("Las contraseñas del certificado no coinciden")
    if len(clave) < easyrsa.MIN_CLAVE:
        raise ValueError("La contraseña del certificado debe tener al menos %d caracteres"
                         % easyrsa.MIN_CLAVE)

    return clave


@router.post("")
def crear_cliente(
    request: Request,
    cn: str = Form(...),
    # Marcada por defecto en el formulario. Un navegador no envía las casillas
    # sin marcar, así que la ausencia significa 'sin contraseña'.
    con_clave: str = Form(None),
    clave: str = Form(""),
    clave2: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        secreto = _clave_pedida(con_clave, clave, clave2)
    except ValueError as e:
        return error_htmx(request, str(e))

    detalle = "clave privada cifrada" if secreto else "clave privada sin contraseña"

    try:
        easyrsa.crear_cliente(cfg(request), cn, secreto)
    except easyrsa.ClaveInvalida as e:
        return error_htmx(request, str(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "crear_cliente", cn, "error", str(e))
        return error_htmx(request, "No se pudo crear '%s': %s" % (cn, e))

    # Se anota QUE lleva contraseña, nunca cuál
    auditar(request, sesion, "crear_cliente", cn, detalle=detalle)

    if secreto:
        mensaje = ("Cliente '%s' creado con la clave privada cifrada. Al conectar se "
                   "le pedirá la contraseña, así que dásela por otra vía distinta "
                   "del propio archivo." % cn)
    else:
        mensaje = ("Cliente '%s' creado sin contraseña. Ojo: su .ovpn es acceso "
                   "directo a la VPN para quien se haga con el archivo." % cn)

    return aviso(request, mensaje, refrescar=EVENTO_REFRESCO)


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
    con_clave: str = Form(None),
    clave: str = Form(""),
    clave2: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Reemite el certificado de un cliente revocado.

    Acepta contraseña porque genera una clave privada nueva: la que tuviera
    antes no se puede recuperar ni reutilizar, así que hay que volver a
    decidirlo. Sin marcar la casilla, la nueva sale sin cifrar.
    """
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    try:
        secreto = _clave_pedida(con_clave, clave, clave2)
    except ValueError as e:
        return error_htmx(request, str(e))

    try:
        easyrsa.restaurar(cfg(request), cn, secreto)
    except easyrsa.ClaveInvalida as e:
        return error_htmx(request, str(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "restaurar", cn, "error", str(e))
        return error_htmx(request, "No se pudo restaurar '%s': %s" % (cn, e))

    auditar(request, sesion, "restaurar", cn,
            detalle="clave privada cifrada" if secreto else "clave privada sin contraseña")
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
