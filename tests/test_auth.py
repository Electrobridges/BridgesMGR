"""
Autenticación, roles, CSRF y bloqueo por intentos.

Son las pruebas que más importan: un fallo aquí expone la administración del
servidor VPN a cualquiera que alcance el puerto.
"""

import pytest

from app import db
from app.auth import COOKIE_NOMBRE

from .conftest import PASSWORD_ADMIN, csrf_de

RUTAS_PROTEGIDAS = ["/", "/conexiones", "/clientes", "/logs", "/configuracion",
                    "/admin/auditoria", "/admin/usuarios"]


@pytest.mark.parametrize("ruta", RUTAS_PROTEGIDAS)
def test_sin_sesion_redirige_al_login(cliente, ruta):
    respuesta = cliente.get(ruta, follow_redirects=False)

    assert respuesta.status_code == 303
    assert respuesta.headers["location"] == "/login"


def test_login_correcto_planta_cookie(cliente, usuarios):
    respuesta = cliente.post(
        "/login",
        data={"usuario": "jefa", "password": PASSWORD_ADMIN},
        follow_redirects=False,
    )

    assert respuesta.status_code == 303
    cookie = respuesta.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()


def test_password_incorrecta(cliente, usuarios):
    respuesta = cliente.post(
        "/login", data={"usuario": "jefa", "password": "equivocada"}
    )

    assert respuesta.status_code == 401
    # El mensaje no debe revelar si el usuario existe
    assert "Usuario o contraseña incorrectos" in respuesta.text


def test_usuario_inexistente_mismo_mensaje(cliente, usuarios):
    respuesta = cliente.post(
        "/login", data={"usuario": "fantasma", "password": "loquesea1234"}
    )

    assert respuesta.status_code == 401
    assert "Usuario o contraseña incorrectos" in respuesta.text


def test_bloqueo_tras_intentos_fallidos(cliente, usuarios, cfg):
    for _ in range(cfg.seguridad.max_intentos_login):
        cliente.post("/login", data={"usuario": "jefa", "password": "mal"})

    # Incluso con la contraseña correcta, ahora está bloqueado
    respuesta = cliente.post(
        "/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN}
    )

    assert respuesta.status_code == 429
    assert "Demasiados intentos" in respuesta.text


def test_login_correcto_limpia_intentos(cliente, usuarios, cfg):
    cliente.post("/login", data={"usuario": "jefa", "password": "mal"})
    cliente.post("/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN},
                 follow_redirects=False)

    assert db.esta_bloqueado(cfg.seguridad.db_path, "jefa|testclient") == 0


def test_usuario_desactivado_no_entra(cliente, usuarios, cfg):
    db.activar_usuario(cfg.seguridad.db_path, "jefa", False)

    respuesta = cliente.post(
        "/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN}
    )

    assert respuesta.status_code == 401


def test_logout_invalida_la_sesion(como_admin, cfg):
    token = como_admin.cookies.get(COOKIE_NOMBRE)
    assert db.obtener_sesion(cfg.seguridad.db_path, token)

    como_admin.post("/logout", follow_redirects=False)

    assert db.obtener_sesion(cfg.seguridad.db_path, token) is None


def test_token_de_sesion_no_se_guarda_en_claro(como_admin, cfg):
    """En la base solo debe estar el SHA-256 del token"""
    token = como_admin.cookies.get(COOKIE_NOMBRE)

    with db.conexion(cfg.seguridad.db_path) as con:
        filas = con.execute("SELECT token_hash FROM sesiones").fetchall()

    assert filas
    assert all(f["token_hash"] != token for f in filas)


# ------------------------------------------------------------------- roles

def test_supervisor_puede_consultar(como_supervisor):
    assert como_supervisor.get("/clientes").status_code == 200
    assert como_supervisor.get("/conexiones").status_code == 200


def test_supervisor_no_puede_revocar(como_supervisor, cfg):
    respuesta = como_supervisor.post(
        "/clientes/alguien/revocar", headers={"X-CSRF-Token": csrf_de(como_supervisor, cfg)}
    )

    assert respuesta.status_code == 403


def test_supervisor_no_entra_en_administracion(como_supervisor):
    assert como_supervisor.get("/admin/usuarios", follow_redirects=False).status_code == 403


def test_supervisor_no_descarga_perfiles(como_supervisor):
    """El .ovpn lleva la clave privada: es acceso a la VPN, solo admin"""
    assert como_supervisor.get("/clientes/daniel/ovpn").status_code == 403


def test_el_superusuario_manda_igual_que_un_admin(como_super):
    """
    El escalón de arriba no puede tener menos permiso que el de abajo. Es lo
    que se rompería si solo_admin siguiera comparando con la cadena 'admin'.
    """
    assert como_super.get("/admin/usuarios").status_code == 200
    assert como_super.get("/clientes").status_code == 200


# -------------------------------------------------------------------- CSRF

def test_mutacion_sin_cabecera_csrf_falla(como_admin):
    respuesta = como_admin.post("/clientes/daniel/revocar")

    assert respuesta.status_code == 403
    assert "CSRF" in respuesta.text


def test_mutacion_con_csrf_equivocado_falla(como_admin):
    respuesta = como_admin.post(
        "/clientes/daniel/revocar", headers={"X-CSRF-Token": "token-inventado"}
    )

    assert respuesta.status_code == 403


def test_htmx_sin_sesion_recibe_redireccion_de_htmx(cliente):
    """HTMX no debe inyectar la página de login dentro de un fragmento"""
    respuesta = cliente.get("/conexiones/tabla", headers={"HX-Request": "true"})

    assert respuesta.status_code == 401
    assert respuesta.headers["HX-Redirect"] == "/login"


# ------------------------------------------------------- cabeceras y sesión

def test_cabeceras_de_seguridad(cliente):
    respuesta = cliente.get("/login")

    assert respuesta.headers["X-Frame-Options"] == "DENY"
    assert respuesta.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in respuesta.headers["Content-Security-Policy"]
    assert respuesta.headers["Cache-Control"] == "no-store"


def test_cambiar_password_cierra_sesiones(como_admin, cfg, csrf_admin):
    respuesta = como_admin.post(
        "/admin/usuarios/mirona/password",
        data={"password": "otra-contrasena-larga"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert "sesiones se han cerrado" in respuesta.text


def test_no_se_puede_borrar_la_cuenta_propia(como_admin, csrf_admin, cfg):
    respuesta = como_admin.post(
        "/admin/usuarios/jefa/borrar", headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert "tu propia cuenta" in respuesta.text


def test_degradar_a_otro_admin_si_queda_alguien_al_mando(como_admin, csrf_admin, cfg, usuarios):
    """El caso normal: hay más de uno al mando, así que degradar vale"""
    ruta = cfg.seguridad.db_path
    db.cambiar_rol(ruta, usuarios["supervisor"], "admin")

    respuesta = como_admin.post(
        "/admin/usuarios/%s/rol" % usuarios["supervisor"],
        data={"rol": "supervisor"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200, respuesta.text
    assert db.obtener_usuario(ruta, usuarios["supervisor"])["rol"] == "supervisor"
