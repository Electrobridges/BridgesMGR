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
