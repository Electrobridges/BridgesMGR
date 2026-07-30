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

PASSWORD_SUPER = "contrasena-super-larga"
PASSWORD_ADMIN = "contrasena-admin-larga"
PASSWORD_SUPERVISOR = "contrasena-supervisor-larga"


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
    """
    Una cuenta de cada escalón de la jerarquía.

    El orden de creación importa y no es decorativo: la primera cuenta de una
    instalación nace superusuario se pida el rol que se pida, así que 'raiz'
    tiene que ir antes que 'jefa' para que 'jefa' sea un admin normal. Hacen
    falta las dos: casi todas las pruebas quieren un admin corriente, y algunas
    quieren comprobar precisamente que no alcanza al superusuario.
    """
    # Normalmente lo hace crear_app, pero esta fixture se puede pedir sin
    # levantar la app y entonces no habría ni tablas.
    db.init_db(cfg.seguridad.db_path)

    db.crear_usuario(cfg.seguridad.db_path, "raiz", PASSWORD_SUPER, "admin")
    db.crear_usuario(cfg.seguridad.db_path, "jefa", PASSWORD_ADMIN, "admin")
    db.crear_usuario(cfg.seguridad.db_path, "mirona", PASSWORD_SUPERVISOR, "supervisor")

    return {"super": "raiz", "admin": "jefa", "supervisor": "mirona"}


def _entrar(cliente, usuario, password):
    respuesta = cliente.post(
        "/login",
        data={"usuario": usuario, "password": password},
        follow_redirects=False,
    )
    assert respuesta.status_code == 303, respuesta.text
    return cliente


@pytest.fixture
def como_super(cliente, usuarios):
    return _entrar(cliente, usuarios["super"], PASSWORD_SUPER)


@pytest.fixture
def como_admin(cliente, usuarios):
    return _entrar(cliente, usuarios["admin"], PASSWORD_ADMIN)


@pytest.fixture
def como_supervisor(cliente, usuarios):
    return _entrar(cliente, usuarios["supervisor"], PASSWORD_SUPERVISOR)


def csrf_de(cliente, cfg):
    """Token CSRF de la sesión que tenga abierta ese cliente"""
    from app.auth import COOKIE_NOMBRE

    sesion = db.obtener_sesion(cfg.seguridad.db_path, cliente.cookies.get(COOKIE_NOMBRE))
    return sesion["csrf"]


@pytest.fixture
def csrf_admin(como_admin, cfg):
    """Token CSRF de la sesión abierta, para las peticiones que mutan"""
    return csrf_de(como_admin, cfg)


@pytest.fixture
def csrf_super(como_super, cfg):
    return csrf_de(como_super, cfg)


@pytest.fixture
def csrf_supervisor(como_supervisor, cfg):
    """
    Para comprobar que a un supervisor se le corta por el rol y no por el CSRF.

    Sin token válido, una ruta prohibida devolvería 403 igualmente y la prueba
    pasaría por el motivo equivocado.
    """
    return csrf_de(como_supervisor, cfg)


def base_de_dos_roles(tmp_path, cuentas, ajustes=None, nombre="antigua.db"):
    """
    Escribe una base tal y como la dejaba la v0.1.0: dos roles y sin TOTP.

    Se construye a mano y no con el esquema actual porque el sentido de estas
    pruebas es justo que la forma vieja siga arrancando. 'cuentas' es una lista
    de (usuario, rol) en el orden en que se crearon, que es el que decide a
    quién le toca ser superusuario.
    """
    import sqlite3

    ruta = str(tmp_path / nombre)
    con = sqlite3.connect(ruta)
    con.executescript("""
        CREATE TABLE usuarios (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario       TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            rol           TEXT    NOT NULL CHECK (rol IN ('admin', 'lector')),
            activo        INTEGER NOT NULL DEFAULT 1,
            creado        TEXT    NOT NULL
        );
        CREATE TABLE ajustes (
            clave TEXT PRIMARY KEY,
            valor TEXT NOT NULL
        );
        CREATE TABLE sesiones (
            token_hash TEXT    PRIMARY KEY,
            usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            csrf       TEXT    NOT NULL,
            creada     TEXT    NOT NULL,
            expira     TEXT    NOT NULL,
            ip         TEXT
        );
    """)

    for usuario, rol in cuentas:
        con.execute(
            "INSERT INTO usuarios (usuario, password_hash, rol, activo, creado)"
            " VALUES (?, 'x', ?, 1, '2026-01-01T00:00:00')",
            (usuario, rol),
        )

    for clave, valor in (ajustes or {}).items():
        con.execute("INSERT INTO ajustes (clave, valor) VALUES (?, ?)", (clave, valor))

    con.commit()
    con.close()
    return ruta
