"""
Gestión de clientes VPN: alta, revocación, restauración, expulsión y descarga
del .ovpn.

Todas las mutaciones exigen rol admin y cabecera CSRF, y quedan registradas en
la auditoría con su resultado.
"""

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from .. import db
from .. import politicas as aplicar_politicas
from ..auth import solo_admin, usuario_actual, verificar_csrf
from ..core import easyrsa, serverconf
from ..core import politicas as pol
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

    # Los archivados salen de la lista activa, pero siguen en la PKI y siguen
    # revocados: esto es solo estado del panel.
    archivados = db.cn_archivados(c.seguridad.db_path)

    politicas = db.listar_politicas(c.seguridad.db_path)
    ahora = datetime.now()

    def fila(cn, estado, conectado):
        p = politicas.get(cn)
        return {
            "cn": cn, "estado": estado, "conectado": conectado,
            "politica": pol.resumen(p),
            # Lo que impide entrar AHORA, aunque el certificado sea válido. Sin
            # esto la tabla diría 'válido' de alguien que no puede conectar.
            "rechazo": pol.TEXTO_MOTIVO.get(pol.motivo_rechazo(p, ahora)) if p else None,
        }

    filas = []
    for cn in certificados["validos"]:
        if cn not in archivados:
            filas.append(fila(cn, "valido", cn in conectados))
    for cn in certificados["revocados"]:
        if cn not in archivados:
            filas.append(fila(cn, "revocado", False))

    filas.sort(key=lambda f: (f["estado"] != "valido", f["cn"].lower()))
    return filas, errores


@router.get("")
def pagina_clientes(request: Request, sesion=Depends(usuario_actual)):
    # Sin 'es_admin': render() ya inyecta 'manda' desde db.ROLES_MANDO. Aquí se
    # comparaba con la cadena 'admin' y al superusuario le desaparecían el
    # formulario de crear y los botones de la tabla.
    ruta = cfg(request).seguridad.db_path
    return render(request, "clientes.html", {
        "reparto": db.reparto_abierto(ruta),
        "max_sesion_global": db.max_sesion_global(ruta),
    })


@router.get("/tabla")
def tabla_clientes(request: Request, sesion=Depends(usuario_actual)):
    filas, errores = _estado_clientes(request)
    return render(request, "partials/tabla_clientes.html", {
        "filas": filas,
        "errores": errores,
    })


@router.get("/archivados")
def lista_archivados(request: Request, sesion=Depends(usuario_actual)):
    """
    El histórico de eliminados, aparte de la tabla.

    Su propio fragmento porque la tabla se recarga sola cada 30 segundos y
    dentro de este hay un <details>: el refresco periódico lo cerraría mientras
    alguien lo está leyendo.
    """
    return render(request, "partials/lista_archivados.html", {
        "archivados": db.listar_archivados(cfg(request).seguridad.db_path),
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
    # Vacío = acceso permanente. Con fecha, es un acceso temporal: el script de
    # conexión lo rechaza a partir de ahí y el vigilante revoca el certificado.
    caduca: str = Form(""),
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

    if caduca.strip():
        try:
            expira = pol.validar_expira(caduca)
        except pol.PoliticaInvalida as e:
            return error_htmx(request, str(e))
        if datetime.strptime(expira, pol.FORMATO_EXPIRA) <= datetime.now():
            return error_htmx(request, "La caducidad tiene que ser una fecha futura")

        # La política ANTES que el certificado: si esto fallara después de
        # emitirlo, quedaría un acceso permanente que se pidió temporal. Una
        # política sin certificado no da acceso a nadie.
        anterior = db.obtener_politica(cfg(request).seguridad.db_path, cn) or pol.vacia()
        nueva = dict(anterior, expira=expira)
        try:
            aplicar_politicas.aplicar(cfg(request), {cn: nueva}, usuario=sesion["usuario"])
        except (pol.PoliticaInvalida, easyrsa.ErrorHelper) as e:
            return error_htmx(request, "No se pudo fijar la caducidad, así que no se ha "
                                       "creado el cliente: %s" % e)
        detalle += "; acceso temporal hasta %s" % expira.replace("T", " ")

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

    # El formulario vuelve vacío en el mismo intercambio: si no, el nombre y las
    # dos contraseñas se quedaban escritos tras crear.
    return aviso(request, mensaje, refrescar=EVENTO_REFRESCO,
                 oob="partials/form_crear_cliente.html")


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

    # Un acceso temporal vencido no se resucita restaurando: el vigilante lo
    # volvería a revocar en un minuto y el script de conexión lo rechazaría
    # mientras tanto. Que se decida a la vista, cambiando la caducidad.
    politica = db.obtener_politica(cfg(request).seguridad.db_path, cn)
    if politica and pol.caducada(politica, datetime.now()):
        return error_htmx(
            request,
            "El acceso temporal de '%s' caducó el %s. Amplía o quita la caducidad "
            "en sus políticas antes de restaurarlo." % (cn, politica["expira"].replace("T", " ")),
        )

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


@router.post("/{cn}/archivar")
def archivar_cliente(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Retira el perfil de la lista activa y lo pasa al histórico de eliminados.

    No toca la PKI, y eso no es una limitación: la CRL se regenera desde
    index.txt, así que borrar de ahí la línea del certificado le devolvería la
    validez en la siguiente revocación de cualquier otro. Archivado sigue
    revocado y sigue bloqueado; solo deja de estorbar.

    Solo se admiten certificados revocados. Ocultar uno válido escondería un
    acceso vivo, que es justo lo contrario de lo que espera quien lo pulsa.
    """
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    # Se pregunta a la PKI y no a _estado_clientes: aquella mezcla el estado de
    # los certificados con quién está conectado ahora, y un management interface
    # caído no puede impedir archivar algo que ya está revocado.
    try:
        certificados = easyrsa.listar_certificados(cfg(request))
    except easyrsa.ErrorHelper as e:
        return error_htmx(request, "No se pudo consultar la PKI: %s" % e)

    if cn in certificados["validos"]:
        auditar(request, sesion, "archivar", cn, "error", "aún válido")
        return error_htmx(
            request,
            "'%s' sigue teniendo un certificado válido. Revócalo primero: si no, "
            "desaparecería de la lista conservando el acceso." % cn,
        )

    if cn not in certificados["revocados"]:
        return error_htmx(request, "'%s' no está en la lista de clientes." % cn)

    db.archivar_cliente(cfg(request).seguridad.db_path, cn, sesion["usuario"])
    auditar(request, sesion, "archivar", cn)

    return aviso(
        request,
        "'%s' pasa a los perfiles eliminados. Su certificado sigue revocado y en "
        "la CRL: se oculta de la lista, no se borra de la PKI." % cn,
        refrescar=EVENTO_REFRESCO,
    )


@router.post("/{cn}/desarchivar")
def desarchivar_cliente(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """Lo devuelve a la lista activa. Sigue revocado; solo vuelve a verse."""
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    if not db.desarchivar_cliente(cfg(request).seguridad.db_path, cn):
        return error_htmx(request, "'%s' no estaba en los eliminados." % cn)

    auditar(request, sesion, "desarchivar", cn)
    return aviso(request, "'%s' vuelve a la lista de clientes." % cn,
                 refrescar=EVENTO_REFRESCO)


@router.post("/reparto/{reparto_id}/aceptar")
def aceptar_reparto(
    request: Request,
    reparto_id: int,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Da por repartidos los perfiles y retira el aviso.

    Se audita porque es una afirmación, no una preferencia de pantalla: alguien
    dice que N personas ya tienen su archivo nuevo. Si luego resulta que no, hay
    que poder saber quién lo dio por hecho y cuándo.
    """
    ruta = cfg(request).seguridad.db_path
    reparto = db.reparto_abierto(ruta)

    if not db.cerrar_reparto(ruta, reparto_id, sesion["usuario"]):
        # Dos pestañas, o el botón pulsado dos veces. No es un error que
        # merezca asustar, pero tampoco se audita algo que no ocurrió.
        return aviso(request, "Ese aviso ya estaba cerrado.", tipo="aviso",
                     oob="partials/aviso_reparto.html")

    sin_descargar = reparto["pendientes"] if reparto else 0
    detalle = ("%d sin descargar" % sin_descargar) if sin_descargar else None
    auditar(request, sesion, "cerrar_reparto", str(reparto_id), detalle=detalle)

    if sin_descargar:
        mensaje = ("Aviso retirado, pero quedaban %d perfiles sin descargar. "
                   "Esos clientes seguirán sin poder conectar." % sin_descargar)
        tipo = "aviso"
    else:
        mensaje = "Aviso retirado. Todos los perfiles se descargaron."
        tipo = "ok"

    return aviso(request, mensaje, tipo=tipo, oob="partials/aviso_reparto.html")


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
    # Si hay un reparto pendiente, este CN deja de estarlo. No hace nada cuando
    # no lo hay, que es el caso normal.
    db.marcar_descargado(cfg(request).seguridad.db_path, cn)

    return Response(
        content=contenido,
        media_type="application/x-openvpn-profile",
        headers={
            "Content-Disposition": 'attachment; filename="%s.ovpn"' % cn,
            "Cache-Control": "no-store",
        },
    )


# ------------------------------------------------------------- políticas

# Cuántas franjas horarias ofrece el formulario. El modelo admite más
# (pol.MAX_FRANJAS); tres cubren los casos reales —laborables, sábado, guardia—
# sin convertir la página en una hoja de cálculo.
FRANJAS_FORMULARIO = 3


def _servidor(c):
    """
    (red, (enganchado, motivo), error) leyendo el server.conf por el helper.

    Un fallo aquí no impide editar: el helper vuelve a validar al aplicar.
    Solo se pierde la ayuda de qué IP están libres.
    """
    try:
        directivas = easyrsa.server_conf(c).get("directivas", [])
    except easyrsa.ErrorHelper as e:
        return None, None, "No se pudo leer el server.conf: %s" % e
    return serverconf.red(directivas), serverconf.gancho(directivas), None


def _politica_del_formulario(anterior, ip_fija, destinos, franjas, expira, max_sesion_min):
    """Lo que llega del formulario, en política normalizada."""
    horario = []
    for i, (dias, desde, hasta) in enumerate(franjas, 1):
        dias = [d for d in dias if d != ""]
        if not dias and not desde and not hasta:
            continue
        try:
            dias = [int(d) for d in dias]
        except ValueError:
            raise pol.PoliticaInvalida("Día no válido en la franja %d" % i)
        if not dias:
            raise pol.PoliticaInvalida("La franja %d tiene horas pero ningún día" % i)
        if not desde or not hasta:
            raise pol.PoliticaInvalida("La franja %d necesita hora de inicio y de fin" % i)
        # Un <input type="time"> no admite 24:00. Terminar a las 00:00 una
        # franja que empieza más tarde solo puede querer decir medianoche.
        if hasta == "00:00" and desde != "00:00":
            hasta = "24:00"
        horario.append({"dias": dias, "desde": desde, "hasta": hasta})

    max_sesion_min = (max_sesion_min or "").strip()
    try:
        maximo = int(max_sesion_min) if max_sesion_min else 0
    except ValueError:
        raise pol.PoliticaInvalida("La duración máxima tiene que ser un número de minutos")

    return pol.normalizar({
        "ip_fija": ip_fija,
        "destinos": [l.strip() for l in (destinos or "").splitlines() if l.strip()],
        "horario": horario,
        "expira": expira,
        "max_sesion_min": maximo,
        # Lo pone el propio panel (las cuotas), no el formulario: se conserva.
        "bloqueo": (anterior or {}).get("bloqueo", ""),
    })


@router.get("/{cn}/politica")
def pagina_politica(request: Request, cn: str, sesion=Depends(usuario_actual)):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    c = cfg(request)
    politica = db.obtener_politica(c.seguridad.db_path, cn) or pol.vacia()
    red, gancho, error = _servidor(c)

    franjas = list(politica["horario"])
    franjas += [{"dias": [], "desde": "", "hasta": ""}] * (FRANJAS_FORMULARIO - len(franjas))

    return render(request, "cliente_politica.html", {
        "cn": cn,
        "politica": politica,
        "franjas": franjas[:max(FRANJAS_FORMULARIO, len(politica["horario"]))],
        "dias": pol.DIAS,
        "red": red,
        "gancho": gancho,
        "error_servidor": error,
        "max_sesion_global": db.max_sesion_global(c.seguridad.db_path),
        "describir_minutos": pol.describir_minutos,
        "rechazo": pol.TEXTO_MOTIVO.get(pol.motivo_rechazo(politica, datetime.now())),
    })


@router.post("/{cn}/politica")
def guardar_politica(
    request: Request,
    cn: str,
    ip_fija: str = Form(""),
    destinos: str = Form(""),
    f1_dias: List[str] = Form([]),
    f1_desde: str = Form(""),
    f1_hasta: str = Form(""),
    f2_dias: List[str] = Form([]),
    f2_desde: str = Form(""),
    f2_hasta: str = Form(""),
    f3_dias: List[str] = Form([]),
    f3_desde: str = Form(""),
    f3_hasta: str = Form(""),
    expira: str = Form(""),
    max_sesion_min: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, str(e))

    c = cfg(request)
    anterior = db.obtener_politica(c.seguridad.db_path, cn)

    try:
        nueva = _politica_del_formulario(
            anterior, ip_fija, destinos,
            [(f1_dias, f1_desde, f1_hasta), (f2_dias, f2_desde, f2_hasta),
             (f3_dias, f3_desde, f3_hasta)],
            expira, max_sesion_min,
        )
        aplicar_politicas.aplicar(c, {cn: nueva}, usuario=sesion["usuario"])
    except pol.PoliticaInvalida as e:
        return error_htmx(request, str(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "politica_cliente", cn, "error", str(e))
        return error_htmx(request, "El servidor no aceptó la política: %s" % e)

    resumen = pol.resumen(nueva)
    auditar(request, sesion, "politica_cliente", cn,
            detalle="; ".join(resumen) if resumen else "sin restricciones")

    mensaje = "Políticas de '%s' guardadas y aplicadas." % cn
    motivo = pol.motivo_rechazo(nueva, datetime.now())
    if motivo:
        mensaje += (" Ahora mismo no puede entrar (%s): si está conectado, se le "
                    "desconectará en menos de un minuto." % pol.TEXTO_MOTIVO[motivo])
    return aviso(request, mensaje, refrescar=EVENTO_REFRESCO)


@router.post("/politicas/global")
def guardar_politica_global(
    request: Request,
    max_sesion_min: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """Duración máxima de sesión para quien no tenga una propia."""
    valor = (max_sesion_min or "").strip()
    try:
        maximo = int(valor) if valor else 0
    except ValueError:
        return error_htmx(request, "La duración máxima tiene que ser un número de minutos")
    if not 0 <= maximo <= pol.MAX_SESION_MIN:
        return error_htmx(request, "Duración máxima fuera de rango")

    try:
        aplicar_politicas.aplicar(cfg(request), max_global=maximo, usuario=sesion["usuario"])
    except pol.PoliticaInvalida as e:
        return error_htmx(request, str(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "politica_global", None, "error", str(e))
        return error_htmx(request, "El servidor no aceptó el cambio: %s" % e)

    texto = ("sin límite" if not maximo else pol.describir_minutos(maximo))
    auditar(request, sesion, "politica_global", None, detalle="sesión máx. %s" % texto)
    return aviso(request, "Duración máxima de sesión para todos: %s." % texto,
                 refrescar=EVENTO_REFRESCO)
