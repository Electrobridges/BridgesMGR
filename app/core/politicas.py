"""
Políticas de acceso por cliente: IP fija, destinos permitidos, horario,
caducidad y duración máxima de sesión.

Se aplican en tres sitios, y cada uno cubre lo que los otros no pueden:

- **Al conectar**, el script `client-connect` que instala el panel lee el
  archivo de políticas que escribe el helper y rechaza a quien esté fuera de
  horario, caducado o bloqueado. Es la única barrera que impide ENTRAR: el
  panel no está en el camino de la conexión y no tiene por qué estar vivo.
- **Durante la sesión**, el vigilante expulsa por el management a quien se
  quede fuera mientras está dentro —se cierra su franja, caduca, supera la
  duración máxima—. Al reconectar, el script de arriba decide.
- **En el tráfico**, las reglas de nftables que escribe el helper limitan a
  qué destinos llega un cliente con IP fija. Sin IP fija no hay nada contra lo
  que escribir la regla, y por eso los destinos la exigen.

Solo stdlib, como todo `core/`. El helper y el script `client-connect`
repiten la validación y la evaluación por su cuenta: están al otro lado de la
frontera de privilegios y no se fían del panel. Hay pruebas que comparan las
tres copias con los mismos casos.
"""

import ipaddress
import re
from datetime import datetime

from .validacion import validar_cn

# Versión del documento que se le pasa al helper. Si cambia la forma, el helper
# rechaza la vieja en vez de interpretarla a medias.
VERSION = 1

# Techos. Están para que un formulario manipulado no le mande al helper un
# documento de megas ni una tabla de nftables de miles de reglas.
MAX_DESTINOS = 32
MAX_FRANJAS = 14
MAX_SESION_MIN = 30 * 24 * 60

# Motivos por los que el propio panel bloquea a un cliente sin revocarlo. Son
# cadenas fijas: el script de conexión las escribe en el log y la plantilla
# decide el texto.
BLOQUEO_CUOTA = "cuota"
BLOQUEOS = (BLOQUEO_CUOTA,)

# Por qué se rechaza o se expulsa. Mismas cadenas en el script de conexión.
MOTIVO_BLOQUEO = "bloqueado"
MOTIVO_CADUCADO = "caducado"
MOTIVO_HORARIO = "fuera_de_horario"
MOTIVO_DURACION = "duracion_maxima"

DIAS = ("lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo")
DIAS_CORTOS = ("L", "M", "X", "J", "V", "S", "D")

FORMATO_EXPIRA = "%Y-%m-%dT%H:%M"

_HORA = re.compile(r'^([01]\d|2[0-3]):([0-5]\d)$|^24:00$')
_DESTINO = re.compile(r'^(?P<red>[0-9./]+)(?::(?P<puerto>\d{1,5})/(?P<proto>tcp|udp))?$')


class PoliticaInvalida(ValueError):
    """La política no supera la validación. El mensaje va a la pantalla."""


def vacia():
    """La política de un cliente sin restricciones"""
    return {
        "ip_fija": "",
        "destinos": [],
        "horario": [],
        "expira": "",
        "max_sesion_min": 0,
        "bloqueo": "",
    }


def es_vacia(politica):
    return normalizar(politica) == vacia()


def _minutos(hora):
    """'08:30' -> 510. '24:00' es el final del día y vale 1440."""
    h, m = hora.split(":")
    return int(h) * 60 + int(m)


def validar_ip(texto):
    try:
        ip = ipaddress.IPv4Address(texto.strip())
    except ValueError:
        raise PoliticaInvalida("'%s' no es una dirección IPv4" % texto)
    return str(ip)


def validar_destino(texto):
    """
    'red[/bits][:puerto/proto]' -> forma canónica.

    Se reescribe en forma canónica —'192.168.1.7' pasa a '192.168.1.7/32'—
    para que dos formas de decir lo mismo no se cuenten como reglas distintas.
    """
    texto = (texto or "").strip()
    m = _DESTINO.match(texto)
    if not m:
        raise PoliticaInvalida(
            "Destino no válido: '%s'. Se escribe como 192.168.1.0/24, "
            "192.168.1.10 o 192.168.1.10:443/tcp" % texto
        )

    try:
        red = ipaddress.IPv4Network(m.group("red"), strict=False)
    except ValueError:
        raise PoliticaInvalida("Red no válida en el destino '%s'" % texto)

    if m.group("puerto") is None:
        return str(red)

    puerto = int(m.group("puerto"))
    if not 1 <= puerto <= 65535:
        raise PoliticaInvalida("Puerto fuera de rango en '%s'" % texto)

    return "%s:%d/%s" % (red, puerto, m.group("proto"))


def validar_franja(franja):
    if not isinstance(franja, dict):
        raise PoliticaInvalida("Franja horaria mal formada")

    dias = franja.get("dias")
    if not isinstance(dias, list) or not dias:
        raise PoliticaInvalida("Cada franja necesita al menos un día")
    if any(not isinstance(d, int) or isinstance(d, bool) or not 0 <= d <= 6 for d in dias):
        raise PoliticaInvalida("Día de la semana no válido en una franja")

    desde = str(franja.get("desde", ""))
    hasta = str(franja.get("hasta", ""))
    for hora in (desde, hasta):
        if not _HORA.match(hora):
            raise PoliticaInvalida("Hora no válida: '%s' (se escribe HH:MM)" % hora)
    if desde == "24:00":
        raise PoliticaInvalida("Una franja no puede empezar a las 24:00")
    if _minutos(desde) >= _minutos(hasta):
        # Las franjas que cruzan la medianoche se escriben como dos: no hay
        # forma de que '22:00-06:00' signifique una sola cosa sin ambigüedad
        # sobre a qué día pertenece cada mitad.
        raise PoliticaInvalida(
            "La franja %s–%s termina antes de empezar. Si cruza la medianoche, "
            "divídela en dos (hasta las 24:00 y desde las 00:00)." % (desde, hasta)
        )

    return {"dias": sorted(set(dias)), "desde": desde, "hasta": hasta}


def validar_expira(texto):
    texto = (texto or "").strip()
    if not texto:
        return ""
    try:
        return datetime.strptime(texto, FORMATO_EXPIRA).strftime(FORMATO_EXPIRA)
    except ValueError:
        raise PoliticaInvalida("Fecha de caducidad no válida: '%s'" % texto)


def normalizar(politica):
    """
    Valida una política y la devuelve en forma canónica.

    Lanza PoliticaInvalida con un mensaje que se puede enseñar tal cual.
    """
    if not isinstance(politica, dict):
        raise PoliticaInvalida("La política debe ser un mapa")

    desconocidas = set(politica) - set(vacia())
    if desconocidas:
        raise PoliticaInvalida("Campos desconocidos: %s" % ", ".join(sorted(desconocidas)))

    p = vacia()

    ip = (politica.get("ip_fija") or "").strip()
    p["ip_fija"] = validar_ip(ip) if ip else ""

    destinos = politica.get("destinos") or []
    if not isinstance(destinos, list):
        raise PoliticaInvalida("Los destinos deben ser una lista")
    if len(destinos) > MAX_DESTINOS:
        raise PoliticaInvalida("Como mucho %d destinos por cliente" % MAX_DESTINOS)
    canon = []
    for d in destinos:
        d = validar_destino(d)
        if d not in canon:
            canon.append(d)
    p["destinos"] = canon

    if p["destinos"] and not p["ip_fija"]:
        # La regla de nftables se escribe contra la IP de origen. Sin IP fija,
        # el cliente recibe una cualquiera del pool y la regla no le alcanza:
        # aceptarla sería prometer un límite que no existe.
        raise PoliticaInvalida("Limitar los destinos exige asignarle una IP fija")

    horario = politica.get("horario") or []
    if not isinstance(horario, list):
        raise PoliticaInvalida("El horario debe ser una lista de franjas")
    if len(horario) > MAX_FRANJAS:
        raise PoliticaInvalida("Como mucho %d franjas horarias" % MAX_FRANJAS)
    p["horario"] = [validar_franja(f) for f in horario]

    p["expira"] = validar_expira(politica.get("expira"))

    maximo = politica.get("max_sesion_min") or 0
    if isinstance(maximo, bool) or not isinstance(maximo, int) or not 0 <= maximo <= MAX_SESION_MIN:
        raise PoliticaInvalida("Duración máxima de sesión fuera de rango")
    p["max_sesion_min"] = maximo

    bloqueo = politica.get("bloqueo") or ""
    if bloqueo and bloqueo not in BLOQUEOS:
        raise PoliticaInvalida("Bloqueo desconocido: %s" % bloqueo)
    p["bloqueo"] = bloqueo

    return p


def documento(politicas, max_sesion_global=0):
    """
    El documento completo que se le pasa al helper por stdin.

    Siempre el conjunto entero y nunca un cambio suelto: así aplicar es
    idempotente, y el archivo del servidor y la base del panel no pueden
    divergir por una petición que se quedó a medias.
    """
    clientes = {}
    for cn, politica in sorted(politicas.items()):
        p = normalizar(politica)
        if p != vacia():
            clientes[validar_cn(cn)] = p

    ips = [p["ip_fija"] for p in clientes.values() if p["ip_fija"]]
    repetidas = sorted({ip for ip in ips if ips.count(ip) > 1})
    if repetidas:
        raise PoliticaInvalida("IP fija asignada a más de un cliente: %s" % ", ".join(repetidas))

    if isinstance(max_sesion_global, bool) or not isinstance(max_sesion_global, int) \
            or not 0 <= max_sesion_global <= MAX_SESION_MIN:
        raise PoliticaInvalida("Duración máxima global fuera de rango")

    return {
        "version": VERSION,
        "global": {"max_sesion_min": max_sesion_global},
        "clientes": clientes,
    }


# ------------------------------------------------------------- evaluación

def dentro_de_horario(horario, ahora):
    """Sin franjas no hay horario: siempre se puede."""
    if not horario:
        return True

    minuto = ahora.hour * 60 + ahora.minute
    dia = ahora.weekday()

    return any(
        dia in f["dias"] and _minutos(f["desde"]) <= minuto < _minutos(f["hasta"])
        for f in horario
    )


def caducada(politica, ahora):
    expira = politica.get("expira")
    if not expira:
        return False
    return ahora >= datetime.strptime(expira, FORMATO_EXPIRA)


def motivo_rechazo(politica, ahora):
    """
    Por qué no puede entrar ahora mismo, o None si puede.

    'ahora' es hora LOCAL del servidor y sin zona, que es en la que se escriben
    los horarios: quien dice 'de 8 a 19' habla de su reloj, no de UTC.
    """
    if politica.get("bloqueo"):
        return MOTIVO_BLOQUEO
    if caducada(politica, ahora):
        return MOTIVO_CADUCADO
    if not dentro_de_horario(politica.get("horario") or [], ahora):
        return MOTIVO_HORARIO
    return None


def max_sesion_efectiva(politica, max_global):
    """La del cliente si la tiene; si no, la global. 0 es sin límite."""
    propia = (politica or {}).get("max_sesion_min") or 0
    return propia or max_global or 0


def motivo_expulsion(politica, max_global, segundos_dentro, ahora):
    """
    Por qué hay que sacar ya a una conexión en curso, o None.

    Lo mismo que al conectar, más la duración: esa solo se puede comprobar con
    la sesión ya abierta.
    """
    motivo = motivo_rechazo(politica or {}, ahora)
    if motivo:
        return motivo

    maximo = max_sesion_efectiva(politica, max_global)
    if maximo and segundos_dentro is not None and segundos_dentro >= maximo * 60:
        return MOTIVO_DURACION

    return None


# ------------------------------------------------------------ presentación

def describir_horario(horario):
    """'L–V 08:00–19:00; S 09:00–13:00' para la tabla de clientes"""
    partes = []
    for f in horario:
        dias = f["dias"]
        if len(dias) > 2 and dias == list(range(dias[0], dias[-1] + 1)):
            texto_dias = "%s–%s" % (DIAS_CORTOS[dias[0]], DIAS_CORTOS[dias[-1]])
        else:
            texto_dias = ",".join(DIAS_CORTOS[d] for d in dias)
        partes.append("%s %s–%s" % (texto_dias, f["desde"], f["hasta"]))
    return "; ".join(partes)


TEXTO_MOTIVO = {
    MOTIVO_BLOQUEO: "bloqueado por el panel",
    MOTIVO_CADUCADO: "acceso caducado",
    MOTIVO_HORARIO: "fuera de su horario",
    MOTIVO_DURACION: "superó la duración máxima de sesión",
}


def resumen(politica):
    """Etiquetas cortas para la tabla de clientes, en orden de importancia."""
    p = politica or vacia()
    partes = []
    if p.get("bloqueo"):
        partes.append("bloqueado (%s)" % p["bloqueo"])
    if p.get("expira"):
        fecha = datetime.strptime(p["expira"], FORMATO_EXPIRA)
        partes.append("caduca %s" % fecha.strftime("%d/%m/%Y %H:%M"))
    if p.get("horario"):
        partes.append(describir_horario(p["horario"]))
    if p.get("max_sesion_min"):
        partes.append("sesión máx. %s" % describir_minutos(p["max_sesion_min"]))
    if p.get("ip_fija"):
        partes.append("IP %s" % p["ip_fija"])
    if p.get("destinos"):
        n = len(p["destinos"])
        partes.append("%d destino%s" % (n, "" if n == 1 else "s"))
    return partes


def describir_minutos(minutos):
    if minutos % 1440 == 0:
        return "%d d" % (minutos // 1440)
    if minutos % 60 == 0:
        return "%d h" % (minutos // 60)
    if minutos > 60:
        return "%d h %d min" % divmod(minutos, 60)
    return "%d min" % minutos
