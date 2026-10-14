"""
Bloqueo automático de IPs que insisten en entrar sin poder: fail2ban, pero
leyendo los sucesos que el panel ya guarda en vez de volver a leer el log.

Qué cuenta y qué no:

- **Cuenta** lo que hace un desconocido: paquetes sin la clave tls-crypt,
  handshakes TLS que no terminan, certificados que no son de esta CA.
- **No cuenta** el certificado revocado ni el rechazo por política. Esos son
  clientes legítimos a los que se les ha cortado el acceso, que reintentan
  solos cada pocos segundos; si comparten la IP pública de una oficina,
  bloquearla dejaría fuera a toda la oficina por culpa de un portátil.

El bloqueo vive en un set de nftables con caducidad: lo quita el núcleo solo,
aunque el panel esté parado. La lista blanca (por defecto, las redes
privadas) no se bloquea nunca de forma automática.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from . import db, notificar
from .core import easyrsa, eventos_vpn

AJUSTE_ACTIVO = "bloqueo_auto"
AJUSTE_UMBRAL = "bloqueo_umbral"
AJUSTE_VENTANA = "bloqueo_ventana_min"
AJUSTE_DURACION = "bloqueo_duracion_min"
AJUSTE_LISTA_BLANCA = "bloqueo_lista_blanca"

POR_DEFECTO = {
    AJUSTE_ACTIVO: "0",
    AJUSTE_UMBRAL: "10",
    AJUSTE_VENTANA: "10",
    AJUSTE_DURACION: "60",
    AJUSTE_LISTA_BLANCA: "127.0.0.0/8\n10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16",
}

TIPOS_QUE_CUENTAN = {eventos_vpn.RECHAZO_CLAVE, eventos_vpn.RECHAZO_TLS,
                     eventos_vpn.RECHAZO_CERTIFICADO}

MAX_DURACION_MIN = 30 * 24 * 60


class AjusteInvalido(ValueError):
    pass


def ajustes(ruta):
    a = {clave: db.obtener_ajuste(ruta, clave, valor) for clave, valor in POR_DEFECTO.items()}
    return {
        "activo": a[AJUSTE_ACTIVO] == "1",
        "umbral": int(a[AJUSTE_UMBRAL]),
        "ventana_min": int(a[AJUSTE_VENTANA]),
        "duracion_min": int(a[AJUSTE_DURACION]),
        "lista_blanca": [l for l in a[AJUSTE_LISTA_BLANCA].splitlines() if l.strip()],
    }


def _entero(texto, nombre, minimo, maximo):
    try:
        valor = int(str(texto).strip())
    except ValueError:
        raise AjusteInvalido("%s tiene que ser un número" % nombre)
    if not minimo <= valor <= maximo:
        raise AjusteInvalido("%s tiene que estar entre %d y %d" % (nombre, minimo, maximo))
    return valor


def lista_blanca(texto):
    redes = []
    for linea in (texto or "").splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            redes.append(str(ipaddress.IPv4Network(linea, strict=False)))
        except ValueError:
            raise AjusteInvalido("Red no válida en la lista blanca: '%s'" % linea)
    return redes


def guardar_ajustes(ruta, activo, umbral, ventana_min, duracion_min, blanca):
    umbral = _entero(umbral, "El umbral", 3, 10000)
    ventana = _entero(ventana_min, "La ventana", 5, 1440)
    duracion = _entero(duracion_min, "La duración", 1, MAX_DURACION_MIN)
    redes = lista_blanca(blanca)

    db.guardar_ajuste(ruta, AJUSTE_ACTIVO, "1" if activo else "0")
    db.guardar_ajuste(ruta, AJUSTE_UMBRAL, str(umbral))
    db.guardar_ajuste(ruta, AJUSTE_VENTANA, str(ventana))
    db.guardar_ajuste(ruta, AJUSTE_DURACION, str(duracion))
    db.guardar_ajuste(ruta, AJUSTE_LISTA_BLANCA, "\n".join(redes))
    return ajustes(ruta)


def en_lista_blanca(ip, redes):
    try:
        direccion = ipaddress.IPv4Address(ip)
    except ValueError:
        return True  # lo que no es una IPv4 no se intenta bloquear
    return any(direccion in ipaddress.IPv4Network(r) for r in redes)


def candidatas(ruta, ahora=None):
    """[(ip, rechazos)] que superan el umbral y no están ya bloqueadas."""
    a = ajustes(ruta)
    ahora = ahora or datetime.now(timezone.utc)
    desde = (ahora - timedelta(minutes=a["ventana_min"])).isoformat()
    ya = {b["ip"] for b in db.bloqueos_activos(ruta)}

    return sorted(
        (ip, n) for ip, n in db.rechazos_por_ip(ruta, TIPOS_QUE_CUENTAN, desde).items()
        if n >= a["umbral"] and ip not in ya and not en_lista_blanca(ip, a["lista_blanca"])
    )


def revisar(cfg, ahora=None):
    """Lo llama el vigilante tras ingerir. Devuelve las IP bloqueadas ahora."""
    ruta = cfg.seguridad.db_path
    a = ajustes(ruta)
    if not a["activo"]:
        return []

    nuevas = candidatas(ruta, ahora)
    if not nuevas:
        return []

    try:
        easyrsa.bloqueos(cfg, bloquear=[(ip, a["duracion_min"]) for ip, _ in nuevas])
    except easyrsa.ErrorHelper as e:
        notificar.auditar_sistema(cfg, "bloquear_ip", ", ".join(ip for ip, _ in nuevas),
                                  "error", str(e))
        return []

    for ip, n in nuevas:
        motivo = "%d intentos fallidos en %d min" % (n, a["ventana_min"])
        db.registrar_bloqueo(ruta, ip, a["duracion_min"], motivo, notificar.ACTOR_SISTEMA)
        notificar.auditar_sistema(cfg, "bloquear_ip", ip,
                                  detalle="%s; bloqueada %d min" % (motivo, a["duracion_min"]))
    return [ip for ip, _ in nuevas]


def bloquear(cfg, ip, minutos, usuario, motivo="a mano"):
    ip = str(ipaddress.IPv4Address(ip.strip()))
    easyrsa.bloqueos(cfg, bloquear=[(ip, minutos)])
    db.registrar_bloqueo(cfg.seguridad.db_path, ip, minutos, motivo, usuario)
    return ip


def desbloquear(cfg, ip):
    ip = str(ipaddress.IPv4Address(ip.strip()))
    easyrsa.bloqueos(cfg, desbloquear=[ip])
    db.levantar_bloqueo(cfg.seguridad.db_path, ip)
    return ip
