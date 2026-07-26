"""Fixtures compartidas: configuración temporal, app y clientes autenticados"""

import pytest
from fastapi.testclient import TestClient

from app import db
from app.config import (
    ClienteOvpnCfg,
    Config,
    OpenVPNCfg,
    SeguridadCfg,
    ServidorCfg,
)
from app.main import crear_app

PASSWORD_ADMIN = "contrasena-admin-larga"
PASSWORD_LECTOR = "contrasena-lector-larga"


@pytest.fixture
def cfg(tmp_path):
    return Config(
        servidor=ServidorCfg(host_bind="127.0.0.1", puerto=55443, tls_cert="", tls_key=""),
        openvpn=OpenVPNCfg(
            log_path=str(tmp_path / "openvpn.log"),
            status_path=str(tmp_path / "status.log"),
            mgmt_host="127.0.0.1",
            # Puerto cerrado a propósito: así el fallback al archivo de status
            # se ejercita en todos los tests sin montar un servidor falso.
            mgmt_port=1,
            easyrsa_path=str(tmp_path / "easy-rsa"),
        ),
        cliente_ovpn=ClienteOvpnCfg(remote_host="vpn.ejemplo.com"),
        seguridad=SeguridadCfg(
            db_path=str(tmp_path / "panel.db"),
            usar_sudo=False,
            helper=str(tmp_path / "helper-inexistente"),
            # TestClient habla http://, y una cookie Secure no viajaría
            cookie_segura=False,
        ),
    )


@pytest.fixture
def app(cfg):
    return crear_app(cfg)


@pytest.fixture
def cliente(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def usuarios(cfg):
    """Crea un admin y un lector en la base del panel"""
    db.crear_usuario(cfg.seguridad.db_path, "jefa", PASSWORD_ADMIN, "admin")
    db.crear_usuario(cfg.seguridad.db_path, "mirona", PASSWORD_LECTOR, "lector")
    return {"admin": "jefa", "lector": "mirona"}


def _entrar(cliente, usuario, password):
    respuesta = cliente.post(
        "/login",
        data={"usuario": usuario, "password": password},
        follow_redirects=False,
    )
    assert respuesta.status_code == 303, respuesta.text
    return cliente


@pytest.fixture
def como_admin(cliente, usuarios):
    return _entrar(cliente, usuarios["admin"], PASSWORD_ADMIN)


@pytest.fixture
def como_lector(cliente, usuarios):
    return _entrar(cliente, usuarios["lector"], PASSWORD_LECTOR)


@pytest.fixture
def csrf_admin(como_admin, cfg):
    """Token CSRF de la sesión abierta, para las peticiones que mutan"""
    from app.auth import COOKIE_NOMBRE

    token = como_admin.cookies.get(COOKIE_NOMBRE)
    sesion = db.obtener_sesion(cfg.seguridad.db_path, token)
    return sesion["csrf"]
