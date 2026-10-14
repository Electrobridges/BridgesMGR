"""
Métricas en formato Prometheus: GET /metrics con 'Authorization: Bearer'.

Apagado salvo que config.yaml traiga seguridad.metricas_token. No usa la
sesión del panel —Prometheus no inicia sesión— sino ese token, comparado en
tiempo constante.

Todo sale de lo que el panel ya tiene a mano: el archivo de status o el
management, la base y la caché de caducidades. Nada llama al helper, así que
un scrape cada 15 segundos no ejecuta nada como root.
"""

import hmac
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from .. import __version__, bloqueos, caducidades, db, trafico, vigilante
from ..core import conexiones, eventos_vpn, salud
from .comun import cfg

router = APIRouter()

TIPO = "text/plain; version=0.0.4; charset=utf-8"


def _etiqueta(valor):
    """Escapa un valor de etiqueta según el formato de exposición."""
    return str(valor).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Metricas:
    def __init__(self):
        self.lineas = []

    def familia(self, nombre, tipo, ayuda):
        self.lineas.append("# HELP %s %s" % (nombre, ayuda))
        self.lineas.append("# TYPE %s %s" % (nombre, tipo))

    def valor(self, nombre, valor, **etiquetas):
        if etiquetas:
            texto = ",".join('%s="%s"' % (k, _etiqueta(v)) for k, v in sorted(etiquetas.items()))
            self.lineas.append("%s{%s} %s" % (nombre, texto, valor))
        else:
            self.lineas.append("%s %s" % (nombre, valor))

    def texto(self):
        return "\n".join(self.lineas) + "\n"


def _segundos(iso):
    try:
        fecha = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return int(fecha.timestamp())


def generar(c):
    ruta = c.seguridad.db_path
    m = _Metricas()

    m.familia("ovpnweb_info", "gauge", "Versión del panel")
    m.valor("ovpnweb_info", 1, version=__version__)

    estado = db.obtener_ajuste(ruta, vigilante.AJUSTE_SERVICIO, "")
    if estado:
        m.familia("ovpnweb_servicio_activo", "gauge",
                  "1 si OpenVPN estaba activo en la última vuelta del vigilante")
        m.valor("ovpnweb_servicio_activo", 1 if estado == "activo" else 0)

    activas, fuente, _ = conexiones.obtener_conexiones(c)
    m.familia("ovpnweb_estado_legible", "gauge",
              "1 si se pudo leer quién está conectado (management o archivo de status)")
    m.valor("ovpnweb_estado_legible", 1 if fuente else 0)
    m.familia("ovpnweb_clientes_conectados", "gauge", "Conexiones activas")
    m.valor("ovpnweb_clientes_conectados", len(activas))

    m.familia("ovpnweb_sesion_bytes_recibidos", "gauge",
              "Bytes recibidos del cliente en la sesión en curso")
    for con in activas:
        m.valor("ovpnweb_sesion_bytes_recibidos", con.get("bytes_recv", 0), cn=con.get("user"))
    m.familia("ovpnweb_sesion_bytes_enviados", "gauge",
              "Bytes enviados al cliente en la sesión en curso")
    for con in activas:
        m.valor("ovpnweb_sesion_bytes_enviados", con.get("bytes_sent", 0), cn=con.get("user"))

    m.familia("ovpnweb_trafico_mes_bytes", "gauge", "Tráfico acumulado del mes en curso")
    for cn, (r, e) in sorted(db.trafico_mes(ruta, trafico.mes_actual()).items()):
        m.valor("ovpnweb_trafico_mes_bytes", r, cn=cn, sentido="recibido")
        m.valor("ovpnweb_trafico_mes_bytes", e, cn=cn, sentido="enviado")

    actual = caducidades.cache(ruta)
    if actual:
        datos = actual["datos"]
        m.familia("ovpnweb_certificados_validos", "gauge", "Certificados de cliente válidos")
        m.valor("ovpnweb_certificados_validos", len(datos.get("clientes") or {}))
        m.familia("ovpnweb_certificado_caduca_timestamp", "gauge",
                  "Momento de caducidad (epoch) de cada certificado")
        for clave, iso in (("ca", datos.get("ca")), ("servidor", datos.get("servidor"))):
            if _segundos(iso):
                m.valor("ovpnweb_certificado_caduca_timestamp", _segundos(iso), tipo=clave, cn="")
        for cn, iso in sorted((datos.get("clientes") or {}).items()):
            if _segundos(iso):
                m.valor("ovpnweb_certificado_caduca_timestamp", _segundos(iso), tipo="cliente", cn=cn)

    try:
        fecha, _dias = salud.caducidad_crl("%s/pki/crl.pem" % c.openvpn.easyrsa_path.rstrip("/"))
        m.familia("ovpnweb_crl_caduca_timestamp", "gauge", "Momento de caducidad (epoch) de la CRL")
        m.valor("ovpnweb_crl_caduca_timestamp", int(fecha.timestamp()))
    except salud.SinCRL:
        pass

    m.familia("ovpnweb_ips_bloqueadas", "gauge", "IPs bloqueadas ahora en el cortafuegos")
    m.valor("ovpnweb_ips_bloqueadas", len(db.bloqueos_activos(ruta)))
    m.familia("ovpnweb_bloqueo_automatico", "gauge", "1 si el bloqueo automático está activo")
    m.valor("ovpnweb_bloqueo_automatico", 1 if bloqueos.ajustes(ruta)["activo"] else 0)

    desde = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    m.familia("ovpnweb_rechazos_24h", "gauge", "Conexiones rechazadas en las últimas 24 h, por tipo")
    for tipo in sorted(eventos_vpn.FALLOS):
        total = sum(db.rechazos_por_ip(ruta, {tipo}, desde).values())
        m.valor("ovpnweb_rechazos_24h", total, tipo=tipo)

    return m.texto()


@router.get("/metrics")
def metricas(request: Request):
    c = cfg(request)
    token = c.seguridad.metricas_token
    if not token:
        return Response(status_code=404)

    cabecera = request.headers.get("Authorization", "")
    esperado = "Bearer %s" % token
    if not hmac.compare_digest(cabecera.encode(), esperado.encode()):
        return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})

    return PlainTextResponse(generar(c), media_type=TIPO)
