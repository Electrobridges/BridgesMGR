"""
Ingesta de los sucesos de la VPN: del log de OpenVPN a la base del panel.

Antes la pestaña leía el archivo en vivo cada vez que alguien la abría, y de
ahí salían sus dos techos: la cola que se leía y, por encima, logrotate, que
vacía el log cada semana. El historial visible era el trozo más corto de los
dos, unos días.

Aquí se le da la vuelta: un lector con cursor pasa cada pocos minutos, se lleva
solo lo que se ha escrito desde la última vez y lo guarda en `eventos_vpn`. El
log pasa a ser un archivo **de paso** y el historial vive en la base, donde
dura lo que el administrador diga y se consulta con SQL en vez de releyendo
megas de texto en cada clic. De paso ocupa mucho menos: solo entran los
sucesos, no las veinte líneas de ruido que OpenVPN escribe alrededor de cada
conexión.

Quien llama es el vigilante, que ya corre en su propio hilo. **Un solo
escritor**: si esto se hiciera al pintar la página, dos peticiones a la vez
ingerirían el mismo tramo y lo duplicarían, porque lo único que impide repetir
es el cursor.

Lo que este módulo NO puede arreglar: un rechazo cuyo 'VERIFY OK' quedó en el
tramo anterior pierde el CN, porque la atribución por 'ip:puerto' vive dentro
de una sola pasada de parse_eventos(). Pasa solo si el corte cae justo entre
dos líneas escritas en el mismo segundo, y degrada a un CN vacío —nunca a uno
equivocado—, que es como ya se comporta un rechazo temprano.
"""

import os
from datetime import datetime, timezone

from . import db
from .core import eventos_vpn

# Cuántas pasadas seguidas como mucho en una misma vuelta. En marcha normal
# basta una —lo escrito en cinco minutos son unos kilobytes—; varias son para la
# primera vuelta sobre un log que ya venía escrito de antes, que a un solo
# BLOQUE_MAX por vuelta tardaría una hora en ponerse al día. Con techo, para no
# dejar al hilo del vigilante leyendo un log gigante mientras lo demás espera:
# lo que no entre se lee en la vuelta siguiente, que el cursor queda puesto.
PASADAS_MAX = 8

# Estado entre vueltas, en `ajustes` para que sobreviva a un reinicio.
AJUSTE_CURSOR = "eventos_vpn_cursor"
AJUSTE_ULTIMA = "eventos_vpn_ultima"
AJUSTE_AVISOS = "eventos_vpn_avisos"
AJUSTE_HUECO = "eventos_vpn_hueco"

AVISO_VERB = (
    "Hay log pero ningún suceso reconocible. Suele ser un 'verb' demasiado "
    "bajo en el server.conf: con 'verb 3' se registran las conexiones y los "
    "rechazos."
)

AVISO_SIN_FECHAS = (
    "El log no fecha sus líneas, así que no se puede decir cuánto duró cada "
    "sesión. Lo causa el '--suppress-timestamps' con el que la unidad de "
    "OpenVPN que empaqueta Debian arranca el servidor; no se quita desde el "
    "server.conf, hace falta un añadido a la unidad: 'systemctl edit "
    "openvpn-server@server' y repetir su ExecStart sin esa bandera."
)


def _cursor(ruta_db):
    try:
        return max(0, int(db.obtener_ajuste(ruta_db, AJUSTE_CURSOR, "0") or 0))
    except ValueError:
        # Un ajuste ilegible no puede dejar al panel sin ingerir para siempre:
        # se vuelve a empezar por el principio del archivo, que como mucho
        # repite un tramo, en vez de callarse y no guardar nada nunca más.
        return 0


def _ultima(ruta_db):
    """Cuándo se leyó por última vez, o None si nunca"""
    marca = db.obtener_ajuste(ruta_db, AJUSTE_ULTIMA, "")
    try:
        return datetime.fromisoformat(marca) if marca else None
    except ValueError:
        return None


def _ahora():
    return datetime.now(timezone.utc).isoformat()


def _modificado(ruta):
    return datetime.fromtimestamp(os.path.getmtime(ruta), timezone.utc)


def _rescatar_rotado(ruta, offset, ultima):
    """
    El tramo que se quedó en la copia que dejó logrotate. (lineas, hueco).

    Con 'copytruncate' —que es como lo instala deploy/instalar-openvpn.sh, para
    no tener que mandarle un SIGHUP a OpenVPN y cortarle el túnel a todo el
    mundo— la rotación copia el archivo a '.1' y luego vacía el original. Lo
    escrito entre la última vuelta y ese vaciado solo está en la copia, así que
    se va a buscar allí. Sin esto se perdería una semana entera cada vez que el
    panel estuviera parado en el momento de rotar.

    'hueco' dice por qué no se ha podido, y no es lo mismo que no haber
    encontrado nada: un agujero en un registro de accesos se cuenta, no se deja
    en blanco para que parezca que esa semana no entró nadie.
    """
    rotado = ruta + ".1"

    # Dos rotaciones o más desde la última vuelta: entonces '.1' ya no es la
    # copia de lo que estábamos leyendo, es la de la semana siguiente, y leerla
    # por nuestro desplazamiento daría texto de la mitad de otro archivo.
    for siguiente in (rotado + ".gz", ruta + ".2", ruta + ".2.gz"):
        if os.path.isfile(siguiente) and ultima and _modificado(siguiente) > ultima:
            return [], "el log rotó más de una vez mientras el panel no miraba"

    if not os.path.isfile(rotado):
        return [], "el log se vació y no quedó copia en %s" % rotado

    if os.path.getsize(rotado) < offset:
        return [], "%s no contiene el tramo que faltaba" % rotado

    if ultima and _modificado(rotado) < ultima:
        return [], "%s es de una rotación anterior" % rotado

    try:
        lineas, _, _ = eventos_vpn.leer_desde(rotado, offset)
    except OSError as e:
        return [], "no se pudo leer %s: %s" % (rotado, e)

    return lineas, None


def _diagnostico(ruta_db, lineas, eventos):
    """
    Qué hay que decirle a quien mire la pestaña, a la vista de lo leído.

    Se calcula sobre el tramo recién leído y no sobre la tabla entera: la
    pregunta es cómo está escribiendo el servidor **ahora**, y recorrer un año
    de filas cada cinco minutos para contestarla no compensa.

    Lo del 'verb' sí mira la tabla, pero solo para saber si está vacía: un
    tramo sin sucesos es de lo más normal a media conexión, y solo significa
    algo cuando no se ha reconocido nada nunca.
    """
    avisos = []

    if lineas and not eventos and not db.hay_eventos_vpn(ruta_db):
        avisos.append(AVISO_VERB)

    if eventos and not any(e["ts"] for e in eventos):
        avisos.append(AVISO_SIN_FECHAS)

    return avisos


def ingerir(cfg):
    """
    Lee lo nuevo del log y lo guarda. Devuelve cuántos sucesos ha guardado.

    Repite mientras haya más por leer, hasta PASADAS_MAX: cada pasada se lleva
    como mucho un BLOQUE_MAX, y en la primera vuelta de una instalación que ya
    llevaba semanas escribiendo log hay bastante más que eso.

    Lo que impide leer —sin ruta, sin archivo, sin permiso— no se anota aquí:
    lo comprueba en vivo avisos() cada vez que alguien abre la pestaña, que es
    cuando importa y cuando además está al día.
    """
    total = 0

    # Cuándo se miró la última vez, leído UNA vez y no en cada pasada: entre dos
    # pasadas de la misma vuelta pasan milisegundos, y una rotación que cayera
    # justo ahí se compararía contra una marca de hace un instante y parecería
    # vieja, declarando un hueco que no existe.
    ultima = _ultima(cfg.seguridad.db_path)

    for _ in range(PASADAS_MAX):
        guardados, lineas = _una_pasada(cfg, ultima)
        total += guardados
        if not lineas:
            break

    return total


def _una_pasada(cfg, ultima):
    """Una lectura y su escritura. Devuelve (guardados, cuántas líneas leyó)."""
    ruta_db = cfg.seguridad.db_path
    ruta = cfg.openvpn.log_path

    if eventos_vpn.revisar_archivo(ruta):
        return 0, 0

    offset = _cursor(ruta_db)

    try:
        lineas, cursor, truncado = eventos_vpn.leer_desde(ruta, offset)
    except OSError as e:
        db.guardar_ajuste(ruta_db, AJUSTE_AVISOS, "No se pudo leer %s: %s." % (ruta, e))
        return 0, 0

    if truncado:
        rescatadas, hueco = _rescatar_rotado(ruta, offset, ultima)
        lineas = rescatadas + lineas
        if hueco:
            db.guardar_ajuste(
                ruta_db, AJUSTE_HUECO,
                "%s\t%s" % (_ahora(), hueco),
            )

    # parse_eventos() los devuelve del más reciente al más antiguo, que es como
    # se enseñan; se guardan al revés porque el id es lo que luego los ordena y
    # tiene que seguir el orden del log.
    eventos = eventos_vpn.parse_eventos(lineas)
    guardados = db.guardar_eventos_vpn(ruta_db, reversed(eventos))

    db.guardar_ajuste(ruta_db, AJUSTE_CURSOR, cursor)
    db.guardar_ajuste(ruta_db, AJUSTE_ULTIMA, _ahora())

    # Solo se reescribe el diagnóstico cuando ha habido algo que mirar: si no,
    # una vuelta tranquila borraría el aviso que dejó la anterior.
    if lineas:
        db.guardar_ajuste(ruta_db, AJUSTE_AVISOS,
                          "\n".join(_diagnostico(ruta_db, lineas, eventos)))

    return guardados, len(lineas)


# ------------------------------------------------------------- importación

def importar_rotados(cfg):
    """
    Recupera de los archivos ya rotados lo anterior a lo que ya está guardado.

    Es de una sola vez y a mano: sirve para la instalación que estrena esto,
    donde el log lleva semanas rotando y en la base no hay nada. La ingesta
    normal no puede hacerlo —lee hacia delante desde un cursor— y meterlo en
    ella significaría releer ocho archivos cada cinco minutos para no
    encontrar nada nuevo.

    **Idempotente sin llevar ninguna cuenta**: solo entra lo anterior al
    suceso fechado más antiguo que ya hay. Lo que no es anterior ya lo trajo
    la ingesta, y al terminar el corte pasa a ser lo recién importado, así que
    repetirlo no mete nada dos veces. No hace falta recordar qué archivos se
    leyeron, que además se renombran solos en cada rotación.

    Devuelve un resumen: qué archivos miró, cuántos sucesos entraron, de qué
    fecha a cuál, y lo que haya que advertir.
    """
    ruta_db = cfg.seguridad.db_path
    ruta = cfg.openvpn.log_path
    resumen = {"archivos": [], "sucesos": 0, "desde": "", "hasta": "", "avisos": []}

    if not ruta:
        resumen["avisos"].append("No hay 'openvpn.log_path' configurado.")
        return resumen

    resumen["archivos"] = eventos_vpn.archivos_rotados(ruta)

    if not resumen["archivos"]:
        resumen["avisos"].append(
            "No hay archivos rotados junto a %s. Si logrotate los guarda en "
            "otro sitio, no hay nada que recuperar desde aquí." % ruta
        )
        return resumen

    corte = db.ts_mas_antiguo_vpn(ruta_db)

    # Hay historia guardada pero ninguna fila fechada: entonces no hay forma de
    # saber qué parte de los archivos rotados ya entró, y meterlos enteros la
    # duplicaría. Se dice, con el arreglo, en vez de duplicar en silencio.
    if corte is None and db.hay_eventos_vpn(ruta_db):
        resumen["avisos"].append(
            "Los sucesos ya guardados no llevan fecha, así que no se puede "
            "saber qué parte de los archivos rotados falta. Pon fecha al log "
            "(deploy/fechas-log.sh) y vuelve a intentarlo cuando la tabla "
            "tenga sucesos fechados."
        )
        return resumen

    lineas = []
    for archivo in resumen["archivos"]:
        try:
            lineas += eventos_vpn.leer_rotado(archivo)
        except (OSError, EOFError) as e:
            # Un '.gz' a medio escribir o sin permiso no puede tirar abajo la
            # recuperación de los otros siete.
            resumen["avisos"].append("No se pudo leer %s: %s" % (archivo, e))

    # De más antiguo a más reciente, que es como hay que insertarlos: el id
    # ordena la tabla y tiene que seguir el orden de los hechos.
    candidatos = list(reversed(eventos_vpn.parse_eventos(lineas)))

    if corte:
        candidatos = [e for e in candidatos if e["ts"] and e["ts"] < corte]
    elif any(not e["ts"] for e in candidatos):
        resumen["avisos"].append(
            "Algunos sucesos de los archivos rotados no llevan fecha. Entran "
            "igual —el suceso es el mismo— pero no tendrán cuándo, y no se "
            "podrá volver a importar sobre ellos."
        )

    resumen["sucesos"] = db.importar_eventos_vpn(ruta_db, candidatos)

    fechados = [e["ts"] for e in candidatos if e["ts"]]
    if fechados:
        resumen["desde"], resumen["hasta"] = fechados[0], fechados[-1]

    return resumen


def avisos(cfg):
    """
    Lo que hay que decir en la pestaña de VPN, de lo más urgente a lo de fondo.

    Mezcla dos cosas a propósito: lo que se comprueba en el momento —que el
    archivo siga ahí y se pueda leer— y lo que solo se sabe habiendo leído,
    que lo dejó anotado la última ingesta. Si esto solo mirase lo guardado, un
    log que dejó de ser legible ayer no se notaría hasta que alguien echara en
    falta una conexión.
    """
    ruta_db = cfg.seguridad.db_path
    mensajes = eventos_vpn.revisar_archivo(cfg.openvpn.log_path)

    if not mensajes and not db.obtener_ajuste(ruta_db, AJUSTE_ULTIMA, ""):
        mensajes.append(
            "El panel todavía no ha leído el log de OpenVPN. Lo hace el "
            "vigilante cada cinco minutos, y este arranca con el servicio del "
            "panel; si esto no cambia, mira que el servicio esté en marcha."
        )

    mensajes += [a for a in (db.obtener_ajuste(ruta_db, AJUSTE_AVISOS, "") or "").split("\n") if a]

    # El hueco se queda puesto para siempre, y no es descuido: el agujero que
    # anuncia tampoco se cierra. Lo que se perdió se perdió, y quien audite
    # este registro dentro de seis meses tiene derecho a saber que ese tramo
    # falta en vez de leer una semana tranquila que nunca existió.
    hueco = db.obtener_ajuste(ruta_db, AJUSTE_HUECO, "")
    if hueco:
        cuando, _, motivo = hueco.partition("\t")
        mensajes.append(
            "Faltan sucesos: el %s %s. Los que se escribieron en ese tramo no "
            "están guardados y no se pueden recuperar."
            % (cuando[:19].replace("T", " "), motivo or "hubo una rotación")
        )

    return mensajes
