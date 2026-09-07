"""
Carga de configuración desde YAML.

El mismo archivo lo leen dos procesos con privilegios distintos: el panel
(como usuario 'ovpnweb') y el helper privilegiado (como root). Por eso es
root:ovpnweb 0640 y el helper NUNCA acepta rutas por argumento: si las
tomara del panel, un panel comprometido podría apuntar easyrsa a cualquier
sitio y escalar a root.
"""

import os
from dataclasses import dataclass, field
from typing import List

import yaml

RUTA_POR_DEFECTO = "/etc/ovpn-web/config.yaml"


@dataclass
class ServidorCfg:
    host_bind: str = "127.0.0.1"
    puerto: int = 55443
    tls_cert: str = "/etc/ovpn-web/tls/cert.pem"
    tls_key: str = "/etc/ovpn-web/tls/key.pem"


@dataclass
class OpenVPNCfg:
    log_path: str = "/var/log/openvpn/openvpn.log"
    status_path: str = "/var/log/openvpn/status.log"
    mgmt_host: str = "127.0.0.1"
    mgmt_port: int = 7505
    easyrsa_path: str = "/etc/openvpn/easy-rsa"
    servicio: str = "openvpn@server"
    # Vacío = el helper prueba las dos rutas estándar. Solo lo usa él, para
    # averiguar con qué certificado se identifica el servidor y excluirlo de la
    # lista de clientes.
    server_conf: str = ""
    # Vacío = se deduce del certificado anterior. Se declara a mano solo si esa
    # deducción no sirve en una instalación rara.
    cn_servidor: str = ""


@dataclass
class ClienteOvpnCfg:
    """Datos para armar el .ovpn que se descarga desde el panel"""
    remote_host: str = ""
    remote_puerto: int = 1194
    proto: str = "udp"
    tls_crypt: str = "/etc/openvpn/tls-crypt.key"
    cipher: str = "AES-256-CBC"
    dns: List[str] = field(default_factory=list)


@dataclass
class CorreoCfg:
    servidor: str = ""
    puerto: int = 587
    usuario: str = ""
    password: str = ""
    desde: str = ""
    destinatarios: List[str] = field(default_factory=list)
    tls: bool = True


@dataclass
class DiscordCfg:
    # La URL del webhook ES la credencial: quien la tenga escribe en ese canal.
    webhook: str = ""


@dataclass
class NotificacionesCfg:
    """
    Destinos de las alertas.

    Viven aquí y no en la tabla `ajustes` a propósito, al revés que la política
    de TOTP: este archivo es root:ovpnweb 0640, así que el panel lo lee y no lo
    escribe. Un panel comprometido puede callar las alertas —eso se avisa antes
    de apagarlas— pero no puede redirigirlas a otro buzón ni a otro canal.
    """
    correo: CorreoCfg = field(default_factory=CorreoCfg)
    discord: DiscordCfg = field(default_factory=DiscordCfg)


@dataclass
class SeguridadCfg:
    helper: str = "/usr/local/sbin/ovpn-web-helper"
    usar_sudo: bool = True
    db_path: str = "/var/lib/ovpn-web/ovpn-web.db"
    # Vacío = junto a la base, en <dir de db_path>/respaldos. Va en el YAML y
    # no en la tabla `ajustes` a propósito: el panel no puede escribir este
    # archivo, así que quien entre en la web no puede mandar copias enteras de
    # la base a una ruta de su elección.
    respaldos_dir: str = ""
    duracion_sesion_min: int = 60
    max_intentos_login: int = 5
    bloqueo_login_min: int = 15
    cookie_segura: bool = True


@dataclass
class Config:
    servidor: ServidorCfg = field(default_factory=ServidorCfg)
    openvpn: OpenVPNCfg = field(default_factory=OpenVPNCfg)
    cliente_ovpn: ClienteOvpnCfg = field(default_factory=ClienteOvpnCfg)
    seguridad: SeguridadCfg = field(default_factory=SeguridadCfg)
    notificaciones: NotificacionesCfg = field(default_factory=NotificacionesCfg)


def _seccion(datos, clave, clase):
    """
    Construye una dataclass rechazando las claves desconocidas del YAML.

    Rechazar y no ignorar: una errata en un nombre de clave pasaría inadvertida
    como valor por defecto, y en este archivo los valores por defecto apuntan a
    otra instalación.
    """
    bruto = datos.get(clave) or {}
    if not isinstance(bruto, dict):
        raise ValueError("La sección '%s' debe ser un mapa" % clave)

    validas = {f.name for f in clase.__dataclass_fields__.values()}
    desconocidas = set(bruto) - validas
    if desconocidas:
        raise ValueError(
            "Claves desconocidas en '%s': %s" % (clave, ", ".join(sorted(desconocidas)))
        )

    return clase(**bruto)


def cargar_config(ruta=None):
    """
    Carga la configuración desde YAML.

    Orden: argumento explícito, variable OVPN_WEB_CONFIG, ruta por defecto.
    """
    ruta = ruta or os.environ.get("OVPN_WEB_CONFIG") or RUTA_POR_DEFECTO

    with open(ruta, "r", encoding="utf-8") as f:
        datos = yaml.safe_load(f) or {}

    if not isinstance(datos, dict):
        raise ValueError("El archivo de configuración debe ser un mapa YAML")

    return Config(
        servidor=_seccion(datos, "servidor", ServidorCfg),
        openvpn=_seccion(datos, "openvpn", OpenVPNCfg),
        cliente_ovpn=_seccion(datos, "cliente_ovpn", ClienteOvpnCfg),
        seguridad=_seccion(datos, "seguridad", SeguridadCfg),
        notificaciones=_notificaciones(datos),
    )


def _notificaciones(datos):
    """
    La única sección con dos niveles, y por eso no vale _seccion() a secas.

    Se comprueban las claves desconocidas en los tres niveles, por el mismo
    motivo que en el resto: una errata aquí dejaría un canal silencioso sin
    decirlo, que es el peor fallo posible en algo que existe para avisar.
    """
    bruto = datos.get("notificaciones") or {}
    if not isinstance(bruto, dict):
        raise ValueError("La sección 'notificaciones' debe ser un mapa")

    desconocidas = set(bruto) - {"correo", "discord"}
    if desconocidas:
        raise ValueError("Claves desconocidas en 'notificaciones': %s"
                         % ", ".join(sorted(desconocidas)))

    return NotificacionesCfg(
        correo=_seccion(bruto, "correo", CorreoCfg),
        discord=_seccion(bruto, "discord", DiscordCfg),
    )
