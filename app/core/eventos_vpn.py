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

# Cuántas líneas del final se miran. El log crece sin límite si nadie lo rota,
# y cargarlo entero para enseñar los últimos sucesos no compensa.
LINEAS_MAX = 5000

_FECHA = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'

# 2026-07-29 23:26:49 daniel/192.168.1.50:54321 SIGTERM[soft,...] received
# 2026-07-29 23:26:49 192.168.1.50:54321 VERIFY OK: depth=0, CN=daniel
# 2026-07-29 23:26:49 Initialization Sequence Completed
_LINEA = re.compile(
    r'^(?P<ts>' + _FECHA + r')\s+'
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
            "ts": m.group("ts"),
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

    return (eventos[:limite] if limite else eventos), avisos
