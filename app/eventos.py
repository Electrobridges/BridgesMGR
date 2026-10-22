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
import re
from datetime import datetime, timezone

from . import db
from .core import eventos_vpn
from .idiomas import N_, t

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


# ------------------------------------------------------- los avisos en pantalla

# Los avisos que se enseñan en la pestaña de VPN. Viven en dos sitios: los que
# comprueba el ingestor en el momento, y los que dejó anotados la última vez
# que leyó el log. Los del ingestor se guardan en la base y se leen tal cual;
# los que devuelve revisar_archivo() vienen ya con la ruta puesta.
#
# El diccionario vive aquí y no en app/core/eventos_vpn.py porque ese módulo no
# se toca: sus expresiones regulares leen el log de OpenVPN, y esto es lo que
# se enseña en la pantalla. Hay una prueba que comprueba que los textos de
# aquí siguen casando con los de allí.
AVISOS = (
    N_("No hay 'openvpn.log_path' configurado: no se puede leer nada."),
    N_("No existe %(ruta)s. Si tu server.conf no tiene 'log-append', OpenVPN "
       "escribe al journal y aquí no hay nada que leer."),
    N_("No se puede leer %(ruta)s. El panel corre como 'ovpnweb'; el archivo "
       "debe ser legible por el grupo 'adm'."),
    N_("Algunas sesiones empiezan antes del tramo que se empareja (los "
       "%(n)s sucesos más recientes), así que de ellas solo consta la salida."),
    N_("El panel todavía no ha leído el log de OpenVPN. Lo hace el vigilante "
       "cada cinco minutos, y este arranca con el servicio del panel; si esto "
       "no cambia, mira que el servicio esté en marcha."),
    N_("Faltan sucesos: el %(cuando)s %(motivo)s. Los que se escribieron en ese "
       "tramo no están guardados y no se pueden recuperar."),
    N_("Hay log pero ningún suceso reconocible. Suele ser un 'verb' demasiado "
       "bajo en el server.conf: con 'verb 3' se registran las conexiones y los "
       "rechazos."),
    N_("El log no fecha sus líneas, así que no se puede decir cuánto duró cada "
       "sesión. Lo causa el '--suppress-timestamps' con el que la unidad de "
       "OpenVPN que empaqueta Debian arranca el servidor; no se quita desde el "
       "server.conf, hace falta un añadido a la unidad: 'systemctl edit "
       "openvpn-server@server' y repetir su ExecStart sin esa bandera."),
    # El que guarda el ingestor cuando no puede leer el log. Se termina en
    # punto, como se guarda, para que el patrón case con él.
    N_("No se pudo leer %(ruta)s: %(error)s."),
)

# Los motivos por los que falta un tramo. Van dentro del aviso, así que se
# traducen por separado. Cada uno es una plantilla con sus huecos, como los
# avisos de arriba.
MOTIVOS = (
    N_("el log rotó más de una vez mientras el panel no miraba"),
    N_("el log se vació y no quedó copia en %(ruta)s"),
    N_("%(ruta)s no contiene el tramo que faltaba"),
    N_("%(ruta)s es de una rotación anterior"),
    N_("no se pudo leer %(ruta)s: %(error)s"),
    N_("hubo una rotación"),
)


def _traducir_con(plantillas, texto):
    """
    Traduce un texto que casa con una de las plantillas, con sus huecos.

    Un texto que no casa con ninguna se devuelve tal cual: puede ser un aviso
    de una versión anterior, y eso no es motivo para romper la página.
    """
    plantilla, valores = _casar(plantillas, texto)
    if plantilla is None:
        return texto
    return t(plantilla, **valores)


def _casar(plantillas, texto):
    """
    (plantilla, valores) si el texto casa con alguna plantilla, o (None, None).

    Los avisos guardados vienen con los huecos ya rellenos (la ruta, la
    fecha), así que para encontrar su plantilla se construye una expresión
    regular a partir de ella.
    """
    for plantilla in plantillas:
        # Se trocea ANTES de escapar: re.escape() escape los paréntesis del
        # hueco, y entonces el patrón ya no se parece al texto.
        trozos = re.split(r"%\(\w+\)s", plantilla)
        patron = re.escape(trozos[0])
        for trozo in trozos[1:]:
            patron += "(.+?)" + re.escape(trozo)

        m = re.fullmatch(patron, texto or "", re.S)
        if m:
            valores = dict(zip(re.findall(r"%\((\w+)\)s", plantilla), m.groups()))
            return plantilla, valores
    return None, None


def traducir_aviso(texto):
    """Un aviso de la pestaña de VPN en el idioma de quien lo lee."""
    return _traducir_con(AVISOS, texto)


def traducir_motivo(motivo):
    """El motivo de un tramo que falta, por separado: va dentro del aviso."""
    plantilla, valores = _casar(MOTIVOS, motivo)
    if plantilla is None:
        # Un motivo que no se reconoce —de una versión vieja— no se cuela en
        # el texto en otro idioma: se dice lo mismo que dicen los de
        # rotación, que es lo que pasó. Ojo: comparar el texto traducido con
        # el original NO vale para saber si se ha reconocido: en español son
        # lo mismo.
        return t("hubo una rotación")
    return t(plantilla, **valores)


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

    if total:
        vigilar_perfiles_compartidos(cfg)

    return total


# Un perfil compartido se delata solo: sin 'duplicate-cn', cada vez que uno de
# los dos conecta, OpenVPN echa al otro, que reconecta y echa al primero. Un
# portátil que cambia de wifi a 4G desplaza su propia sesión UNA vez; lo que no
# hace es ir y volver entre dos IP varias veces en pocos minutos.
VENTANA_COMPARTIDO_MIN = 15
DESPLAZAMIENTOS_COMPARTIDO = 3
# No se repite el aviso del mismo perfil antes de esto: mientras sigan
# peleándose saldría uno cada cinco minutos.
SILENCIO_COMPARTIDO_H = 6
AJUSTE_COMPARTIDO = "perfil_compartido_aviso"


def es_vaiven(ips):
    """
    ¿La secuencia de IP que desplazaron sesiones parece dos sitios peleándose?

    Al menos DESPLAZAMIENTOS_COMPARTIDO desplazamientos, desde dos IP o más, y
    con la IP cambiando de uno al siguiente más de una vez: ir de A a B es
    cambiar de red, ir de A a B y volver a A ya no.
    """
    if len(ips) < DESPLAZAMIENTOS_COMPARTIDO or len(set(ips)) < 2:
        return False
    cambios = sum(1 for a, b in zip(ips, ips[1:]) if a != b)
    return cambios >= 2


def vigilar_perfiles_compartidos(cfg, ahora=None):
    """Avisa de los perfiles que parecen estar en dos sitios a la vez."""
    from datetime import timedelta

    from . import notificar

    ruta_db = cfg.seguridad.db_path
    ahora = ahora or datetime.now(timezone.utc)
    desde = (ahora - timedelta(minutes=VENTANA_COMPARTIDO_MIN)).isoformat()

    avisados = {}
    for linea in (db.obtener_ajuste(ruta_db, AJUSTE_COMPARTIDO, "") or "").splitlines():
        cn, _, cuando = linea.partition("\t")
        avisados[cn] = cuando

    cambiado = False
    for cn, ips in db.duplicadas_recientes(ruta_db, desde).items():
        if not es_vaiven(ips):
            continue
        anterior = avisados.get(cn)
        if anterior:
            try:
                if ahora - datetime.fromisoformat(anterior) < timedelta(hours=SILENCIO_COMPARTIDO_H):
                    continue
            except ValueError:
                pass

        notificar.auditar_sistema(
            cfg, "perfil_compartido", cn,
            detalle="%d sesiones desplazadas en %d min desde %s"
                    % (len(ips), VENTANA_COMPARTIDO_MIN, ", ".join(sorted(set(ips)))),
        )
        avisados[cn] = ahora.isoformat()
        cambiado = True

    if cambiado:
        db.guardar_ajuste(ruta_db, AJUSTE_COMPARTIDO,
                          "\n".join("%s\t%s" % par for par in sorted(avisados.items())))


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
            % (cuando[:19].replace("T", " "),
               traducir_motivo(motivo) if motivo else traducir_motivo("hubo una rotación"))
        )

    # Los avisos se guardan en español, que es como los escribió el ingestor,
    # y se traducen aquí, al enseñarlos: quien los lee puede estar usando el
    # panel en otro idioma.
    return [traducir_aviso(m) for m in mensajes]
