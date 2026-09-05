"""
Eventos de la VPN, leídos del log de OpenVPN.

No van a la tabla `auditoria` a propósito. Aquella registra acciones **del
panel** y tiene columna `usuario`, que es una cuenta del panel; una conexión de
VPN no tiene cuenta del panel, tiene un CN de certificado. Son dos cosas
distintas, y mezclarlas dejaría esa tabla sin responder «quién hizo qué en el
panel», que es justo para lo que existe.

Solo stdlib, como todo `core/`: se prueba sin levantar la web ni tener OpenVPN.

Lo que se puede reconocer depende del `verb` del servidor. A `verb 3` están
todas estas líneas; por debajo, varias no se escriben. Por eso `leer_eventos()`
devuelve también avisos: una tabla vacía no puede parecerse a «no ha entrado
nadie» cuando en realidad es que no hay nada que leer.
"""

import os
import re
from datetime import datetime

# Cuántas líneas del final se miran. El log crece sin límite si nadie lo rota,
# y cargarlo entero para enseñar los últimos sucesos no compensa.
LINEAS_MAX = 5000

_FECHA = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'

# 2026-07-29 23:26:49 daniel/192.168.1.50:54321 SIGTERM[soft,...] received
# 2026-07-29 23:26:49 192.168.1.50:54321 VERIFY OK: depth=0, CN=daniel
# 2026-07-29 23:26:49 Initialization Sequence Completed
#
# La fecha es OPCIONAL, y no por tolerancia: la unidad que Debian empaqueta
# arranca OpenVPN con '--suppress-timestamps', así que en una instalación de
# paquete NINGUNA línea la lleva. Exigirla dejaba el log entero fuera —cero
# sucesos con el archivo lleno de conexiones— y el server.conf no puede
# desactivar esa bandera. Sin fecha se pierde el cuándo, no el qué: el resto
# de la línea es idéntico, así que el suceso se reconoce igual y quien lea
# 'ts' se encuentra una cadena vacía, no un None que reviente más adelante.
_LINEA = re.compile(
    r'^(?:(?P<ts>' + _FECHA + r')\s+)?'
    r'(?:(?:(?P<cn>[^\s/]+)/)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<puerto>\d+)\s+)?'
    r'(?P<msg>.*)$'
)

_CN_EN_MENSAJE = re.compile(r'CN\s*=\s*([^\s,]+)')

# Tipos de suceso. La plantilla decide el texto a partir de esto, así que son
# cadenas fijas y no frases.
CONEXION = "conexion"
DESCONEXION = "desconexion"
RECHAZO_REVOCADO = "rechazo_revocado"
RECHAZO_CERTIFICADO = "rechazo_certificado"
RECHAZO_TLS = "rechazo_tls"
RECHAZO_CLAVE = "rechazo_clave"
ARRANQUE = "arranque"
CRL = "crl"

# Qué cuenta como fallo al filtrar en pantalla
FALLOS = {RECHAZO_REVOCADO, RECHAZO_CERTIFICADO, RECHAZO_TLS, RECHAZO_CLAVE}


def _clasificar(msg):
    """
    Devuelve (tipo, detalle) o None si la línea no interesa.

    El orden importa: 'certificate revoked' es un VERIFY ERROR más, y hay que
    reconocerlo antes que el caso general para no perder el motivo.
    """
    if "Peer Connection Initiated" in msg:
        return CONEXION, None

    if "VERIFY ERROR" in msg:
        if "certificate revoked" in msg:
            return RECHAZO_REVOCADO, "certificado revocado"
        if "certificate has expired" in msg:
            return RECHAZO_CERTIFICADO, "certificado caducado"
        return RECHAZO_CERTIFICADO, "no superó la verificación"

    if "AUTH_FAILED" in msg:
        return RECHAZO_CERTIFICADO, "autenticación rechazada"

    if "TLS Error" in msg or "TLS_ERROR" in msg:
        # El síntoma clásico de una clave tls-crypt que no coincide: el cliente
        # trae la vieja tras una rotación. Merece mensaje propio porque el
        # genérico manda a mirar donde no es.
        if "key negotiation failed" in msg:
            return RECHAZO_CLAVE, "la clave tls-crypt/tls-auth del cliente no coincide"
        if "handshake failed" in msg:
            return RECHAZO_TLS, "el handshake TLS no llegó a completarse"
        return None

    if "client-instance exiting" in msg or "client-instance restarting" in msg:
        return DESCONEXION, None

    if "Initialization Sequence Completed" in msg:
        return ARRANQUE, "el servidor OpenVPN quedó operativo"

    if msg.startswith("CRL:"):
        return CRL, msg.strip()

    return None


def _cola(ruta, lineas):
    """Últimas N líneas sin cargar el archivo entero en memoria"""
    with open(ruta, "rb") as f:
        f.seek(0, os.SEEK_END)
        fin = f.tell()
        bloque = 64 * 1024
        datos = b""

        while fin > 0 and datos.count(b"\n") <= lineas:
            salto = min(bloque, fin)
            fin -= salto
            f.seek(fin)
            datos = f.read(salto) + datos

    texto = datos.decode("utf-8", errors="replace")
    return texto.splitlines()[-lineas:]


def parse_eventos(lineas):
    """
    Convierte líneas del log en sucesos, de más reciente a más antiguo.

    OpenVPN prefija con 'ip:puerto' las líneas de una misma sesión, y le
    antepone el CN en cuanto lo conoce. Se aprovecha para atar un rechazo con
    quién lo provocó: sin ese agrupamiento, un VERIFY ERROR es una IP suelta.

    Ojo: un rechazo temprano puede no tener CN por ningún lado, porque la
    conexión murió antes de presentar certificado. En ese caso el CN queda
    vacío, nunca inventado.
    """
    sesiones = {}
    eventos = []

    for linea in lineas:
        m = _LINEA.match(linea)
        if not m:
            continue

        msg = m.group("msg")
        ip = m.group("ip")
        puerto = m.group("puerto")
        clave = "%s:%s" % (ip, puerto) if ip else None

        # 'VERIFY OK: depth=0, CN=daniel' identifica la sesión aunque después
        # falle: se guarda para poder atribuir lo que venga detrás.
        if clave and "VERIFY OK" in msg and "depth=0" in msg:
            cn_visto = _CN_EN_MENSAJE.search(msg)
            if cn_visto:
                sesiones[clave] = cn_visto.group(1)

        clasificado = _clasificar(msg)
        if clasificado is None:
            continue
        tipo, detalle = clasificado

        # El CN puede venir del prefijo, del propio mensaje, o de lo que se
        # aprendió antes en esa misma sesión.
        cn = m.group("cn")
        if not cn:
            entre_corchetes = re.search(r'\[([^\]\s]+)\]\s+Peer Connection', msg)
            if entre_corchetes:
                cn = entre_corchetes.group(1)
        if not cn and tipo in FALLOS:
            en_mensaje = _CN_EN_MENSAJE.search(msg)
            if en_mensaje:
                cn = en_mensaje.group(1)
        if not cn and clave:
            cn = sesiones.get(clave)

        eventos.append({
            "ts": m.group("ts") or "",
            "tipo": tipo,
            "cn": cn or "",
            "ip": ip or "",
            "puerto": puerto or "",
            "detalle": detalle,
            "fallo": tipo in FALLOS,
        })

        if tipo == DESCONEXION and clave:
            sesiones.pop(clave, None)

    eventos.reverse()
    return eventos


def leer_eventos(cfg, limite=None):
    """
    Punto de entrada único: devuelve (eventos, avisos).

    Sin 'limite' los devuelve todos los que haya en la cola del archivo: quien
    llama pagina después, y para paginar hace falta saber cuántos hay. El techo
    real es LINEAS_MAX, que acota la lectura del disco.

    Los avisos existen porque los tres motivos por los que esto sale vacío se
    parecen entre sí y solo uno es normal: que no haya pasado nada, que el panel
    no pueda leer el archivo, o que el servidor escriba a un `verb` tan bajo que
    no registre estas líneas. Sin decirlo, un permiso mal puesto parece calma.
    """
    ruta = cfg.openvpn.log_path
    avisos = []

    if not ruta:
        return [], ["No hay 'openvpn.log_path' configurado: no se puede leer nada."]

    if not os.path.isfile(ruta):
        return [], [
            "No existe %s. Si tu server.conf no tiene 'log-append', OpenVPN "
            "escribe al journal y aquí no hay nada que leer." % ruta
        ]

    try:
        lineas = _cola(ruta, LINEAS_MAX)
    except OSError as e:
        return [], [
            "No se pudo leer %s: %s. El panel corre como 'ovpnweb'; el archivo "
            "debe ser legible por el grupo 'adm'." % (ruta, e)
        ]

    eventos = parse_eventos(lineas)

    if not eventos and lineas:
        avisos.append(
            "Hay log pero ningún suceso reconocible. Suele ser un 'verb' "
            "demasiado bajo en el server.conf: con 'verb 3' se registran las "
            "conexiones y los rechazos."
        )

    # Los sucesos salen igual sin fecha, pero todo lo que dependa del cuándo
    # —las duraciones de la vista de sesiones— se queda sin poder calcularse.
    # Se dice aquí, con el arreglo puesto: el server.conf no tiene manera de
    # desactivar la bandera, así que buscarlo allí es perder la tarde.
    if eventos and not any(e["ts"] for e in eventos):
        avisos.append(
            "El log no fecha sus líneas, así que no se puede decir cuánto "
            "duró cada sesión. Lo causa el '--suppress-timestamps' con el que "
            "la unidad de OpenVPN que empaqueta Debian arranca el servidor; no "
            "se quita desde el server.conf, hace falta un añadido a la unidad: "
            "'systemctl edit openvpn-server@server' y repetir su ExecStart sin "
            "esa bandera."
        )

    return (eventos[:limite] if limite else eventos), avisos


# ---------------------------------------------------------------- sesiones

# Formato con el que OpenVPN fecha cada línea. Es hora **local del servidor**,
# no UTC, y aquí se deja tal cual: convertirla exigiría saber la zona con la
# que corría OpenVPN cuando escribió la línea, que no está en el archivo.
FORMATO_TS = "%Y-%m-%d %H:%M:%S"

# En qué situación quedó una sesión. Son cadenas fijas y no frases: la plantilla
# decide el texto, igual que con los tipos de suceso.
CERRADA = "cerrada"          # entró y salió: la duración es un dato
ABIERTA = "abierta"          # entró y no consta salida; probablemente siga dentro
INTERRUMPIDA = "interrumpida"  # entró, no consta salida, y el servidor arrancó después
SIN_INICIO = "sin_inicio"    # solo consta la salida: su entrada quedó fuera del tramo leído


def _segundos(inicio, fin):
    """
    Duración en segundos, o None si no se puede afirmar.

    Devuelve None ante una diferencia negativa en vez de un número raro: pasa
    si al servidor le cambian la hora entre las dos líneas, y una duración
    negativa en una auditoría es peor que un hueco declarado.
    """
    try:
        a = datetime.strptime(inicio, FORMATO_TS)
        b = datetime.strptime(fin, FORMATO_TS)
    except (ValueError, TypeError):
        return None

    total = int((b - a).total_seconds())
    return total if total >= 0 else None


def formatear_duracion(segundos):
    """
    Duración legible, con dos unidades como mucho: '3 d 4 h', '2 h 33 min'.

    Cadena vacía si no hay duración que dar. Quien llama no tiene que
    acordarse de comprobarlo, igual que con format_bytes.

    Por encima de la hora se dejan de escribir los segundos, que a esa escala
    solo son ruido; por debajo se conservan, porque un cliente que reconecta en
    bucle deja sesiones de segundos y ahí es justo el dato que se busca.
    """
    if segundos is None:
        return ""

    if segundos < 60:
        return "%d s" % segundos

    if segundos < 3600:
        minutos, resto = divmod(segundos, 60)
        return "%d min %d s" % (minutos, resto) if resto else "%d min" % minutos

    if segundos < 86400:
        horas, resto = divmod(segundos, 3600)
        minutos = resto // 60
        return "%d h %d min" % (horas, minutos) if minutos else "%d h" % horas

    dias, resto = divmod(segundos, 86400)
    horas = resto // 3600
    return "%d d %d h" % (dias, horas) if horas else "%d d" % dias


def _sesion(evento):
    return {
        "cn": evento["cn"],
        "ip": evento["ip"],
        "puerto": evento["puerto"],
        "inicio": "",
        "fin": "",
        "segundos": None,
        "estado": ABIERTA,
    }


def emparejar_sesiones(eventos):
    """
    Empareja cada conexión con su desconexión y calcula cuánto duró.

    Recibe lo que devuelve parse_eventos() —de más reciente a más antiguo— y
    devuelve sesiones en ese mismo orden. Por dentro recorre al revés, porque
    emparejar exige ir hacia delante en el tiempo.

    La clave es 'ip:puerto', la misma que ya usa parse_eventos() para atribuir
    un rechazo a su CN. Sirve porque el puerto de origen no se reutiliza
    mientras la sesión vive, así que dos sesiones simultáneas nunca colisionan
    y una reconexión del mismo cliente es una clave distinta.

    Lo que NO se hace, a propósito: inventar el final que falta. Una sesión sin
    desconexión registrada se marca y se dice; ponerle como fin la última línea
    del log daría una duración con pinta de dato que no lo es.
    """
    abiertas = {}
    sesiones = []

    for e in reversed(eventos):
        clave = "%s:%s" % (e["ip"], e["puerto"]) if e["ip"] else None

        if e["tipo"] == CONEXION and clave:
            # Que la clave siguiera abierta significa que aquella sesión nunca
            # registró su salida: el mismo puerto de origen no se reutiliza
            # mientras la anterior vive, así que no puede seguir en pie.
            anterior = abiertas.pop(clave, None)
            if anterior is not None:
                anterior["estado"] = INTERRUMPIDA
                sesiones.append(anterior)

            nueva = _sesion(e)
            nueva["inicio"] = e["ts"]
            abiertas[clave] = nueva

        elif e["tipo"] == DESCONEXION and clave:
            sesion = abiertas.pop(clave, None)

            if sesion is None:
                # Su conexión quedó fuera del tramo de log que se lee. Se
                # muestra igual —salió, y eso consta— pero sin duración.
                sesion = _sesion(e)
                sesion["estado"] = SIN_INICIO
            else:
                sesion["estado"] = CERRADA
                sesion["segundos"] = _segundos(sesion["inicio"], e["ts"])
                # El CN suele venir en la línea de salida y no en la de entrada,
                # o al revés. Vale el que haya.
                sesion["cn"] = sesion["cn"] or e["cn"]

            sesion["fin"] = e["ts"]
            sesiones.append(sesion)

        elif e["tipo"] == ARRANQUE:
            # OpenVPN acaba de arrancar: nada de lo de antes sigue conectado.
            # Sin esto, una sesión de hace semanas se quedaría enseñándose como
            # 'en curso' para siempre.
            for sesion in abiertas.values():
                sesion["estado"] = INTERRUMPIDA
                sesiones.append(sesion)
            abiertas.clear()

    sesiones.extend(abiertas.values())

    # Cada fila se ancla en el momento que la sitúa: su inicio, o su final
    # cuando el inicio no se llegó a leer. El formato de fecha de OpenVPN
    # ordena bien como texto, así que no hace falta convertirlo para esto.
    sesiones.sort(key=lambda s: s["inicio"] or s["fin"], reverse=True)
    return sesiones


def leer_sesiones(cfg, limite=None):
    """
    Punto de entrada único de las sesiones: devuelve (sesiones, avisos).

    Se apoya en leer_eventos() en vez de volver a abrir el archivo, para que
    haya un solo sitio que sepa leer el log y un solo sitio que decida qué
    avisos merece el estado de las cosas.
    """
    eventos, avisos = leer_eventos(cfg)
    sesiones = emparejar_sesiones(eventos)

    if any(s["estado"] == SIN_INICIO for s in sesiones):
        avisos.append(
            "Algunas sesiones empiezan antes del tramo de log que se lee "
            "(las últimas %d líneas), así que de ellas solo consta la salida."
            % LINEAS_MAX
        )

    return (sesiones[:limite] if limite else sesiones), avisos
