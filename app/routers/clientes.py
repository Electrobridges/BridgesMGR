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

from .. import caducidades, db, estadisticas, eventos, trafico
from .. import politicas as aplicar_politicas
from ..auth import solo_admin, usuario_actual, verificar_csrf
from ..core import easyrsa, serverconf
from ..core import politicas as pol
from ..core.conexiones import obtener_conexiones
from ..core.mgmt import ErrorManagement, desconectar_cliente
from ..core.validacion import CNInvalido, validar_cn
from ..idiomas import MensajeError, N_, mensaje, t, tn
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
        errores.append(t("No se pudo consultar la PKI: %(error)s", error=mensaje(e)))

    conexiones, _fuente, errores_con = obtener_conexiones(c)
    errores += errores_con
    conectados = {con["user"] for con in conexiones}

    # Los archivados salen de la lista activa, pero siguen en la PKI y siguen
    # revocados: esto es solo estado del panel.
    archivados = db.cn_archivados(c.seguridad.db_path)

    politicas = db.listar_politicas(c.seguridad.db_path)
    caducan = caducidades.por_cliente(c.seguridad.db_path)
    uso = trafico.uso_mes(c.seguridad.db_path)
    ahora = datetime.now()

    def fila(cn, estado, conectado):
        p = politicas.get(cn)
        # El motivo se calcula una vez: dos llamadas a motivo_rechazo() con
        # dos 'ahora' distintos podían dar condiciones y valores que no
        # casaran, y la tabla enseñaría un motivo que no era el del momento.
        motivo = pol.motivo_rechazo(p, ahora) if p else None
        return {
            "cn": cn, "estado": estado, "conectado": conectado,
            "politica": pol.resumen_traducido(p),
            # Lo que impide entrar AHORA, aunque el certificado sea válido. Sin
            # esto la tabla diría 'válido' de alguien que no puede conectar.
            "rechazo": t(pol.TEXTO_MOTIVO[motivo]) if motivo and motivo in pol.TEXTO_MOTIVO else None,
            # Días que le quedan al CERTIFICADO, solo si son pocos. Es otra
            # cosa que la caducidad de la política: esta no se cambia en el
            # panel, hay que reemitir.
            "cert_caduca": caducan.get(cn) if estado == "valido" else None,
            "uso_mes": trafico.bytes_decimales(uso[cn]) if uso.get(cn) else None,
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


def _reparto_traducido(reparto):
    """
    El reparto pendiente, con su detalle en el idioma de quien lo mira.

    El detalle se guarda en español, que es como lo escribió el panel cuando
    rotó la clave, y es un dato. Pero se enseña, así que se traduce aquí.
    """
    if not reparto:
        return reparto
    return dict(reparto, detalle=eventos.traducir_aviso(reparto["detalle"])
                if reparto.get("detalle") else reparto.get("detalle"))


@router.get("")
def pagina_clientes(request: Request, sesion=Depends(usuario_actual)):
    # Sin 'es_admin': render() ya inyecta 'manda' desde db.ROLES_MANDO. Aquí se
    # comparaba con la cadena 'admin' y al superusuario le desaparecían el
    # formulario de crear y los botones de la tabla.
    ruta = cfg(request).seguridad.db_path
    return render(request, "clientes.html", {
        "reparto": _reparto_traducido(db.reparto_abierto(ruta)),
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

    # OJO: aquí el texto va como literal, sin N_(). El extractor marca como
    # problema una llamada a MensajeError() cuyo texto no sea un literal, y
    # una prueba lo vigila: si el texto venía envuelto en N_(), el extractor
    # se quejaría de esto, no de la traducción.
    if not clave:
        raise MensajeError(
            "Marcaste cifrar la clave privada pero no escribiste ninguna contraseña")
    if clave != clave2:
        raise MensajeError("Las contraseñas del certificado no coinciden")
    if len(clave) < easyrsa.MIN_CLAVE:
        raise MensajeError(
            "La contraseña del certificado debe tener al menos %(n)s caracteres",
            n=easyrsa.MIN_CLAVE)

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
        return error_htmx(request, mensaje(e))

    try:
        secreto = _clave_pedida(con_clave, clave, clave2)
    except ValueError as e:
        return error_htmx(request, mensaje(e))

    detalle = "clave privada cifrada" if secreto else "clave privada sin contraseña"

    if caduca.strip():
        try:
            expira = pol.validar_expira(caduca)
        except pol.PoliticaInvalida as e:
            return error_htmx(request, mensaje(e))
        if datetime.strptime(expira, pol.FORMATO_EXPIRA) <= datetime.now():
            return error_htmx(request, t("La caducidad tiene que ser una fecha futura"))

        # La política ANTES que el certificado: si esto fallara después de
        # emitirlo, quedaría un acceso permanente que se pidió temporal. Una
        # política sin certificado no da acceso a nadie.
        anterior = db.obtener_politica(cfg(request).seguridad.db_path, cn) or pol.vacia()
        nueva = dict(anterior, expira=expira)
        try:
            aplicar_politicas.aplicar(cfg(request), {cn: nueva}, usuario=sesion["usuario"])
        except (pol.PoliticaInvalida, easyrsa.ErrorHelper) as e:
            return error_htmx(request, t("No se pudo fijar la caducidad, así que no se ha "
                                         "creado el cliente: %(error)s", error=mensaje(e)))
        detalle += "; acceso temporal hasta %s" % expira.replace("T", " ")

    try:
        easyrsa.crear_cliente(cfg(request), cn, secreto)
    except easyrsa.ClaveInvalida as e:
        return error_htmx(request, mensaje(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "crear_cliente", cn, "error", str(e))
        return error_htmx(request, t("No se pudo crear '%(cn)s': %(error)s",
                                     cn=cn, error=mensaje(e)))

    caducidades.invalidar(cfg(request).seguridad.db_path)
    # Se anota QUE lleva contraseña, nunca cuál
    auditar(request, sesion, "crear_cliente", cn, detalle=detalle)

    if secreto:
        texto = t("Cliente '%(cn)s' creado con la clave privada cifrada. Al conectar se "
                  "le pedirá la contraseña, así que dásela por otra vía distinta "
                  "del propio archivo.", cn=cn)
    else:
        texto = t("Cliente '%(cn)s' creado sin contraseña. Ojo: su .ovpn es acceso "
                  "directo a la VPN para quien se haga con el archivo.", cn=cn)

    # El formulario vuelve vacío en el mismo intercambio: si no, el nombre y las
    # dos contraseñas se quedaban escritos tras crear.
    return aviso(request, texto, refrescar=EVENTO_REFRESCO,
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
        return error_htmx(request, mensaje(e))

    try:
        easyrsa.revocar(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "revocar", cn, "error", str(e))
        return error_htmx(request, t("No se pudo revocar '%(cn)s': %(error)s",
                                     cn=cn, error=mensaje(e)))

    caducidades.invalidar(cfg(request).seguridad.db_path)
    auditar(request, sesion, "revocar", cn)
    return aviso(
        request,
        t("Acceso de '%(cn)s' revocado y CRL regenerada. Reinicia %(servicio)s para "
          "aplicarlo.", cn=cn, servicio=cfg(request).openvpn.servicio),
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
        return error_htmx(request, mensaje(e))

    try:
        secreto = _clave_pedida(con_clave, clave, clave2)
    except ValueError as e:
        return error_htmx(request, mensaje(e))

    # Un acceso temporal vencido no se resucita restaurando: el vigilante lo
    # volvería a revocar en un minuto y el script de conexión lo rechazaría
    # mientras tanto. Que se decida a la vista, cambiando la caducidad.
    politica = db.obtener_politica(cfg(request).seguridad.db_path, cn)
    if politica and pol.caducada(politica, datetime.now()):
        return error_htmx(
            request,
            t("El acceso temporal de '%(cn)s' caducó el %(fecha)s. Amplía o quita la "
              "caducidad en sus políticas antes de restaurarlo.",
              cn=cn, fecha=politica["expira"].replace("T", " ")),
        )

    try:
        easyrsa.restaurar(cfg(request), cn, secreto)
    except easyrsa.ClaveInvalida as e:
        return error_htmx(request, mensaje(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "restaurar", cn, "error", str(e))
        return error_htmx(request, t("No se pudo restaurar '%(cn)s': %(error)s",
                                     cn=cn, error=mensaje(e)))

    caducidades.invalidar(cfg(request).seguridad.db_path)
    auditar(request, sesion, "restaurar", cn,
            detalle="clave privada cifrada" if secreto else "clave privada sin contraseña")
    return aviso(
        request,
        t("Certificado de '%(cn)s' reemitido. Descarga el nuevo .ovpn: el anterior ya "
          "no sirve.", cn=cn),
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
        return error_htmx(request, mensaje(e))

    c = cfg(request)

    try:
        desconectar_cliente(c.openvpn.mgmt_host, c.openvpn.mgmt_port, cn)
    except ErrorManagement as e:
        # A la auditoría va str(e), que es el mensaje en español: es un dato.
        # Lo que se enseña va traducido, y el de dentro también.
        auditar(request, sesion, "desconectar", cn, "error", str(e))
        return error_htmx(request, t("No se pudo desconectar a '%(cn)s': %(error)s",
                                     cn=cn, error=mensaje(e)))

    auditar(request, sesion, "desconectar", cn)
    return aviso(request, t("'%(cn)s' desconectado.", cn=cn), refrescar=EVENTO_REFRESCO)


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
        return error_htmx(request, mensaje(e))

    # Se pregunta a la PKI y no a _estado_clientes: aquella mezcla el estado de
    # los certificados con quién está conectado ahora, y un management interface
    # caído no puede impedir archivar algo que ya está revocado.
    try:
        certificados = easyrsa.listar_certificados(cfg(request))
    except easyrsa.ErrorHelper as e:
        return error_htmx(request, t("No se pudo consultar la PKI: %(error)s",
                                     error=mensaje(e)))

    if cn in certificados["validos"]:
        auditar(request, sesion, "archivar", cn, "error", "aún válido")
        return error_htmx(
            request,
            t("'%(cn)s' sigue teniendo un certificado válido. Revócalo primero: si no, "
              "desaparecería de la lista conservando el acceso.", cn=cn),
        )

    if cn not in certificados["revocados"]:
        return error_htmx(request, t("'%(cn)s' no está en la lista de clientes.", cn=cn))

    db.archivar_cliente(cfg(request).seguridad.db_path, cn, sesion["usuario"])
    auditar(request, sesion, "archivar", cn)

    return aviso(
        request,
        t("'%(cn)s' pasa a los perfiles eliminados. Su certificado sigue revocado y en "
          "la CRL: se oculta de la lista, no se borra de la PKI.", cn=cn),
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
        return error_htmx(request, mensaje(e))

    if not db.desarchivar_cliente(cfg(request).seguridad.db_path, cn):
        return error_htmx(request, t("'%(cn)s' no estaba en los eliminados.", cn=cn))

    auditar(request, sesion, "desarchivar", cn)
    return aviso(request, t("'%(cn)s' vuelve a la lista de clientes.", cn=cn),
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
        return aviso(request, t("Ese aviso ya estaba cerrado."), tipo="aviso",
                     oob="partials/aviso_reparto.html")

    sin_descargar = reparto["pendientes"] if reparto else 0
    detalle = ("%d sin descargar" % sin_descargar) if sin_descargar else None
    auditar(request, sesion, "cerrar_reparto", str(reparto_id), detalle=detalle)

    if sin_descargar:
        texto = tn("Aviso retirado, pero quedaba %(n)s perfil sin descargar. "
                   "Esos clientes seguirán sin poder conectar.",
                   "Aviso retirado, pero quedaban %(n)s perfiles sin descargar. "
                   "Esos clientes seguirán sin poder conectar.", sin_descargar)
        tipo = "aviso"
    else:
        texto = t("Aviso retirado. Todos los perfiles se descargaron.")
        tipo = "ok"

    return aviso(request, texto, tipo=tipo, oob="partials/aviso_reparto.html")


@router.get("/{cn}/ovpn")
def descargar_ovpn(request: Request, cn: str, sesion=Depends(solo_admin)):
    """
    Descarga el perfil .ovpn con la clave privada embebida.

    Solo admin: este archivo ES el acceso a la VPN. Queda auditado.
    """
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, mensaje(e))

    try:
        contenido = easyrsa.generar_ovpn(cfg(request), cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "descargar_ovpn", cn, "error", str(e))
        return error_htmx(request, t("No se pudo generar el perfil de '%(cn)s': %(error)s",
                                     cn=cn, error=mensaje(e)))

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
    (directivas, error) leyendo el server.conf por el helper.

    Un fallo aquí no impide editar: el helper vuelve a validar al aplicar.
    Solo se pierde la ayuda de qué IP están libres.
    """
    try:
        return easyrsa.server_conf(c).get("directivas", []), None
    except easyrsa.ErrorHelper as e:
        return None, t("No se pudo leer el server.conf: %(error)s", error=mensaje(e))


def _cuota_mb(texto):
    """'5' o '2,5' GB del formulario -> MB enteros. Vacío o 0 = sin cuota."""
    texto = (texto or "").strip().replace(",", ".")
    if not texto:
        return 0
    try:
        gb = float(texto)
    except ValueError:
        raise pol.PoliticaInvalida(N_("La cuota tiene que ser un número de GB"))
    if gb < 0:
        raise pol.PoliticaInvalida(N_("La cuota no puede ser negativa"))
    return int(round(gb * 1000))


def _politica_del_formulario(anterior, ip_fija, destinos, franjas, expira, max_sesion_min,
                             cuota_gb=""):
    """Lo que llega del formulario, en política normalizada."""
    horario = []
    for i, (dias, desde, hasta) in enumerate(franjas, 1):
        dias = [d for d in dias if d != ""]
        if not dias and not desde and not hasta:
            continue
        try:
            dias = [int(d) for d in dias]
        except ValueError:
            raise pol.PoliticaInvalida(N_("Día no válido en la franja %(n)s"), n=i)
        if not dias:
            raise pol.PoliticaInvalida(N_("La franja %(n)s tiene horas pero ningún día"), n=i)
        if not desde or not hasta:
            raise pol.PoliticaInvalida(N_("La franja %(n)s necesita hora de inicio y de fin"), n=i)
        # Un <input type="time"> no admite 24:00. Terminar a las 00:00 una
        # franja que empieza más tarde solo puede querer decir medianoche.
        if hasta == "00:00" and desde != "00:00":
            hasta = "24:00"
        horario.append({"dias": dias, "desde": desde, "hasta": hasta})

    max_sesion_min = (max_sesion_min or "").strip()
    try:
        maximo = int(max_sesion_min) if max_sesion_min else 0
    except ValueError:
        raise pol.PoliticaInvalida(N_("La duración máxima tiene que ser un número de minutos"))

    return pol.normalizar({
        "ip_fija": ip_fija,
        "destinos": [l.strip() for l in (destinos or "").splitlines() if l.strip()],
        "horario": horario,
        "expira": expira,
        "max_sesion_min": maximo,
        "cuota_mb_mes": _cuota_mb(cuota_gb),
        # Lo pone el propio panel (las cuotas), no el formulario: se conserva.
        "bloqueo": (anterior or {}).get("bloqueo", ""),
    })


@router.get("/{cn}/politica")
def pagina_politica(request: Request, cn: str, sesion=Depends(usuario_actual)):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, mensaje(e))

    c = cfg(request)
    politica = db.obtener_politica(c.seguridad.db_path, cn) or pol.vacia()
    directivas, error = _servidor(c)
    red = serverconf.red(directivas) if directivas is not None else None
    gancho = serverconf.gancho(directivas) if directivas is not None else None

    motivo = pol.motivo_rechazo(politica, datetime.now())
    franjas = list(politica["horario"])
    franjas += [{"dias": [], "desde": "", "hasta": ""}] * (FRANJAS_FORMULARIO - len(franjas))

    return render(request, "cliente_politica.html", {
        "cn": cn,
        "politica": politica,
        # El código del bloqueo se guarda y se compara, pero se enseña: aquí
        # va ya traducido, que es lo que se ve en la página.
        "bloqueo_texto": t(pol.TEXTO_BLOQUEO.get(politica["bloqueo"], politica["bloqueo"]))
                         if politica.get("bloqueo") else "",
        "franjas": franjas[:max(FRANJAS_FORMULARIO, len(politica["horario"]))],
        "dias_cortos": pol.dias_cortos_formulario_traducidos(),
        "red": red,
        # El motivo del gancho lo devuelve serverconf ya traducido: es un
        # texto que se enseña, no un dato que se guarde.
        "gancho": gancho,
        "error_servidor": error,
        "max_sesion_global": db.max_sesion_global(c.seguridad.db_path),
        "describir_minutos": pol.describir_minutos_traducido,
        "rechazo": t(pol.TEXTO_MOTIVO[motivo]) if motivo and motivo in pol.TEXTO_MOTIVO else None,
        "dos_pasos": _estado_dos_pasos(c, cn, directivas),
        "uso_mes": trafico.uso_mes(c.seguridad.db_path).get(cn, 0),
        "grafica_trafico": estadisticas.trafico_diario(c.seguridad.db_path, cn),
        "bytes_decimales": trafico.bytes_decimales,
        "bytes_mb": pol.BYTES_MB,
    })


# --------------------------------------------- verificación en dos pasos (VPN)

EMISOR_VPN = "BridgesMGR VPN"


def _estado_dos_pasos(c, cn, directivas, **extra):
    """Contexto de partials/dos_pasos_vpn.html"""
    estado = {"cn": cn, "activada": None, "faltan": None, "error": None,
              "recien": False, "qr": None, "fallo_qr": None, "uri": None,
              "secreto_legible": None, "mensaje": None}
    if directivas is not None:
        estado["faltan"] = serverconf.dos_pasos(directivas)
    try:
        estado["activada"] = cn in easyrsa.totp_vpn(c, "listar")
    except easyrsa.ErrorHelper as e:
        estado["error"] = t("No se pudo consultar: %(error)s", error=mensaje(e))
    estado.update(extra)
    return estado


@router.post("/{cn}/dos-pasos/activar")
def activar_dos_pasos(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    """
    Genera un secreto, se lo da al helper y lo enseña UNA vez como QR.

    El panel no lo guarda: lo tiene en memoria lo que dura esta respuesta. Si
    se pierde antes de escanearlo, se vuelve a activar y sale uno nuevo; el
    anterior deja de valer en ese momento.
    """
    from .. import qr
    from ..core import totp

    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, mensaje(e))

    c = cfg(request)
    secreto = totp.generar_secreto()
    try:
        easyrsa.totp_vpn(c, "alta", cn, secreto)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "dos_pasos_vpn", cn, "error", str(e))
        return render(request, "partials/dos_pasos_vpn.html",
                      {"d": _estado_dos_pasos(c, cn, None, error=mensaje(e))})

    auditar(request, sesion, "dos_pasos_vpn", cn, detalle="activada (secreto nuevo)")

    uri = totp.uri_otpauth(secreto, cn, EMISOR_VPN)
    imagen, fallo = None, None
    try:
        imagen = qr.data_uri(uri)
    except qr.QRNoDisponible as e:
        fallo = mensaje(e)

    return render(request, "partials/dos_pasos_vpn.html", {"d": _estado_dos_pasos(
        c, cn, None, recien=True, qr=imagen, fallo_qr=fallo, uri=uri,
        secreto_legible=totp.formatear_secreto(secreto),
    )})


@router.post("/{cn}/dos-pasos/quitar")
def quitar_dos_pasos(
    request: Request,
    cn: str,
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, mensaje(e))

    c = cfg(request)
    try:
        easyrsa.totp_vpn(c, "baja", cn)
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "dos_pasos_vpn", cn, "error", str(e))
        return render(request, "partials/dos_pasos_vpn.html",
                      {"d": _estado_dos_pasos(c, cn, None, error=mensaje(e))})

    auditar(request, sesion, "dos_pasos_vpn", cn, detalle="quitada")
    return render(request, "partials/dos_pasos_vpn.html", {"d": _estado_dos_pasos(
        c, cn, None, mensaje=t("Quitada. Su perfil actual sigue pidiendo usuario y "
                               "contraseña: descárgale uno nuevo, o que deje la "
                               "contraseña en blanco."))})


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
    cuota_gb: str = Form(""),
    sesion=Depends(solo_admin),
    _csrf=Depends(verificar_csrf),
):
    try:
        cn = validar_cn(cn)
    except CNInvalido as e:
        return error_htmx(request, mensaje(e))

    c = cfg(request)
    anterior = db.obtener_politica(c.seguridad.db_path, cn)

    try:
        nueva = _politica_del_formulario(
            anterior, ip_fija, destinos,
            [(f1_dias, f1_desde, f1_hasta), (f2_dias, f2_desde, f2_hasta),
             (f3_dias, f3_desde, f3_hasta)],
            expira, max_sesion_min, cuota_gb,
        )
        aplicar_politicas.aplicar(c, {cn: nueva}, usuario=sesion["usuario"])
    except pol.PoliticaInvalida as e:
        return error_htmx(request, mensaje(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "politica_cliente", cn, "error", str(e))
        return error_htmx(request, t("El servidor no aceptó la política: %(error)s",
                                     error=mensaje(e)))

    resumen = pol.resumen(nueva)
    auditar(request, sesion, "politica_cliente", cn,
            detalle="; ".join(resumen) if resumen else "sin restricciones")

    texto = t("Políticas de '%(cn)s' guardadas y aplicadas.", cn=cn)
    motivo = pol.motivo_rechazo(nueva, datetime.now())
    if motivo:
        texto += t(" Ahora mismo no puede entrar (%(motivo)s): si está conectado, se le "
                   "desconectará en menos de un minuto.",
                   motivo=t(pol.TEXTO_MOTIVO[motivo]))
    return aviso(request, texto, refrescar=EVENTO_REFRESCO)


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
        return error_htmx(request, t("La duración máxima tiene que ser un número de minutos"))
    if not 0 <= maximo <= pol.MAX_SESION_MIN:
        return error_htmx(request, t("Duración máxima fuera de rango"))

    try:
        aplicar_politicas.aplicar(cfg(request), max_global=maximo, usuario=sesion["usuario"])
    except pol.PoliticaInvalida as e:
        return error_htmx(request, mensaje(e))
    except easyrsa.ErrorHelper as e:
        auditar(request, sesion, "politica_global", None, "error", str(e))
        return error_htmx(request, t("El servidor no aceptó el cambio: %(error)s",
                                     error=mensaje(e)))

    # El detalle de la auditoría es un dato y se queda en español; lo que se
    # enseña se traduce, y por eso 'sin límite' son dos textos distintos.
    texto = ("sin límite" if not maximo else pol.describir_minutos(maximo))
    auditar(request, sesion, "politica_global", None, detalle="sesión máx. %s" % texto)
    # El hueco no se llama %(texto)s: t() ya tiene un parámetro con ese nombre.
    return aviso(request, t("Duración máxima de sesión para todos: %(limite)s.",
                             limite=t("sin límite") if not maximo
                             else pol.describir_minutos_traducido(maximo)),
                 refrescar=EVENTO_REFRESCO)
