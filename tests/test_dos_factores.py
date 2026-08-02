"""
Segundo factor de extremo a extremo: alta, login en dos pasos, política y
restablecimiento.

Lo que se vigila aquí no es que el código funcione —de eso va test_totp.py—
sino que el segundo factor no se pueda esquivar: que el permiso intermedio no
sirva de sesión, que los códigos fallidos gasten intentos, y que un supervisor
obligado no pueda tocar nada hasta activarlo.
"""

import pytest
from fastapi.testclient import TestClient

from app import db
from app.auth import COOKIE_NOMBRE, COOKIE_PENDIENTE
from app.core import totp

from .conftest import PASSWORD_ADMIN, PASSWORD_SUPERVISOR, base_de_dos_roles


@pytest.fixture
def otro_cliente(app):
    """
    Segundo navegador.

    Hace falta porque 'como_admin' y 'como_supervisor' comparten el mismo
    TestClient: pedir los dos en la misma prueba deja la sesión del último.
    """
    with TestClient(app) as c:
        yield c


def entrar(cliente, usuario, password):
    r = cliente.post(
        "/login",
        data={"usuario": usuario, "password": password},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return cliente


def csrf_de(cliente, cfg):
    sesion = db.obtener_sesion(cfg.seguridad.db_path, cliente.cookies.get(COOKIE_NOMBRE))
    return sesion["csrf"]


def codigo_sin_usar(secreto, avance=1):
    """
    Código de un paso todavía no consumido.

    El alta gasta el paso actual, así que un login inmediato tiene que usar el
    siguiente. Sigue dentro de la ventana de tolerancia (±1).
    """
    return totp.codigo(secreto, paso=totp.paso_actual() + avance)


def dar_de_alta(cliente, cfg, usuario):
    """Recorre el alta como lo haría la persona: generar, confirmar."""
    cab = {"X-CSRF-Token": csrf_de(cliente, cfg)}

    r = cliente.post("/perfil/totp/iniciar", headers=cab)
    assert r.status_code == 200, r.text

    secreto = db.obtener_usuario(cfg.seguridad.db_path, usuario)["totp_secret"]
    assert secreto, "el alta debería haber guardado un secreto"

    r = cliente.post(
        "/perfil/totp/confirmar", data={"codigo": totp.codigo(secreto)}, headers=cab
    )
    assert r.status_code == 200, r.text
    return secreto


# ----------------------------------------------------------------------- alta

def test_alta_no_se_activa_hasta_confirmar(como_admin, cfg, usuarios):
    """Un secreto guardado pero sin confirmar no debe bloquear el login"""
    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    como_admin.post("/perfil/totp/iniciar", headers=cab)

    registro = db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])
    assert registro["totp_secret"]
    assert not registro["totp_activado"]


def test_alta_con_codigo_incorrecto_no_activa(como_admin, cfg, usuarios):
    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    como_admin.post("/perfil/totp/iniciar", headers=cab)

    r = como_admin.post("/perfil/totp/confirmar", data={"codigo": "000000"}, headers=cab)

    assert "incorrecto" in r.text.lower()
    assert not db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["totp_activado"]


def test_alta_completa(como_admin, cfg, usuarios):
    dar_de_alta(como_admin, cfg, usuarios["admin"])
    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["totp_activado"]


def test_el_secreto_no_se_reexpone_al_volver_al_perfil(como_admin, cfg, usuarios):
    """
    Una vez dado de alta, el secreto no vuelve a aparecer: quien tome prestada
    una sesión abierta no debe poder clonarse el segundo factor.
    """
    secreto = dar_de_alta(como_admin, cfg, usuarios["admin"])
    assert secreto not in como_admin.get("/perfil").text


def test_alta_exige_csrf(como_admin):
    assert como_admin.post("/perfil/totp/iniciar").status_code == 403


# ---------------------------------------------------------------------- login

def test_login_pide_codigo_cuando_hay_segundo_factor(cliente, cfg, usuarios, como_admin):
    secreto = dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    r = cliente.post(
        "/login",
        data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN},
        follow_redirects=False,
    )

    # Ni redirección ni sesión: solo el permiso intermedio
    assert r.status_code == 200
    assert "dos pasos" in r.text.lower()
    assert cliente.cookies.get(COOKIE_PENDIENTE)
    assert not cliente.cookies.get(COOKIE_NOMBRE)


def test_el_permiso_intermedio_no_es_una_sesion(cliente, cfg, usuarios, como_admin):
    """La contraseña sola no debe abrir ninguna página del panel"""
    dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})

    for ruta in ("/", "/clientes", "/admin/usuarios", "/admin/auditoria"):
        r = cliente.get(ruta, follow_redirects=False)
        assert r.status_code == 303, "%s se abrió sin el segundo factor" % ruta
        assert r.headers["location"] == "/login"


def test_login_completo_con_codigo(cliente, cfg, usuarios, como_admin):
    secreto = dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})
    r = cliente.post(
        "/login/codigo", data={"codigo": codigo_sin_usar(secreto)}, follow_redirects=False
    )

    assert r.status_code == 303
    assert cliente.cookies.get(COOKIE_NOMBRE)
    assert cliente.get("/").status_code == 200


def test_el_codigo_del_alta_no_sirve_ademas_para_entrar(cliente, cfg, usuarios, como_admin):
    """
    El paso que confirma el alta queda consumido: ese mismo código no debe
    valer también como primer login.
    """
    secreto = dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})
    r = cliente.post("/login/codigo", data={"codigo": totp.codigo(secreto)})

    assert r.status_code == 401
    assert not cliente.cookies.get(COOKIE_NOMBRE)


def test_codigo_de_otro_secreto_no_entra(cliente, cfg, usuarios, como_admin):
    dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})
    r = cliente.post("/login/codigo", data={"codigo": totp.codigo(totp.generar_secreto())})

    assert r.status_code == 401
    assert not cliente.cookies.get(COOKIE_NOMBRE)


def test_un_codigo_no_vale_dos_veces(cliente, cfg, usuarios, como_admin):
    """
    Reutilizar el código dentro de su ventana de 30 s no debe funcionar: si no,
    uno interceptado sirve durante media ventana.
    """
    secreto = dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    codigo = codigo_sin_usar(secreto)

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})
    assert cliente.post("/login/codigo", data={"codigo": codigo},
                        follow_redirects=False).status_code == 303

    cliente.post("/logout", headers={"X-CSRF-Token": csrf_de(cliente, cfg)})
    cliente.cookies.clear()

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})
    r = cliente.post("/login/codigo", data={"codigo": codigo}, follow_redirects=False)

    assert r.status_code == 401
    assert not cliente.cookies.get(COOKIE_NOMBRE)


def test_sin_permiso_intermedio_no_se_puede_verificar(cliente, cfg, usuarios):
    """Presentar un código sin haber pasado antes por la contraseña"""
    r = cliente.post("/login/codigo", data={"codigo": "123456"})

    assert r.status_code == 401
    assert not cliente.cookies.get(COOKIE_NOMBRE)


def test_los_codigos_fallidos_gastan_intentos(cliente, cfg, usuarios, como_admin):
    """
    Sin esto el segundo factor sería un campo de 6 dígitos con intentos
    ilimitados, que se agota por fuerza bruta en unas horas.
    """
    dar_de_alta(como_admin, cfg, usuarios["admin"])
    como_admin.post("/logout", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)})

    cliente.post("/login", data={"usuario": usuarios["admin"], "password": PASSWORD_ADMIN})

    for _ in range(cfg.seguridad.max_intentos_login):
        cliente.post("/login/codigo", data={"codigo": "000000"})

    r = cliente.post("/login/codigo", data={"codigo": "000000"})
    assert r.status_code == 429
    assert "intentos" in r.text.lower()


# -------------------------------------------------------------------- política

def test_por_defecto_no_se_exige_a_nadie(app, cfg, usuarios):
    for rol in db.ROLES:
        assert not db.totp_obligatorio(cfg.seguridad.db_path, rol)
    assert not db.exigir_totp_supervisor(cfg.seguridad.db_path)


def test_la_politica_nunca_alcanza_a_quien_manda(app, cfg, usuarios):
    """
    Un admin no puede imponerle el segundo factor a otro admin: si pudiera,
    dejaría fuera a un igual. Cada uno decide el suyo, y al superusuario menos
    todavía, que es la cuenta que no debe poder quedarse fuera.
    """
    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1")

    assert db.totp_obligatorio(cfg.seguridad.db_path, "supervisor")
    for rol in db.ROLES_MANDO:
        assert not db.totp_obligatorio(cfg.seguridad.db_path, rol)


def test_solo_el_admin_cambia_la_politica(como_supervisor, cfg):
    r = como_supervisor.post(
        "/admin/politica/totp-supervisor",
        data={"exigir": 1},
        headers={"X-CSRF-Token": csrf_de(como_supervisor, cfg)},
    )
    assert r.status_code == 403
    assert not db.exigir_totp_supervisor(cfg.seguridad.db_path)


def test_el_admin_impone_la_politica(como_admin, cfg):
    r = como_admin.post(
        "/admin/politica/totp-supervisor",
        data={"exigir": 1},
        headers={"X-CSRF-Token": csrf_de(como_admin, cfg)},
    )

    assert r.status_code == 200
    assert db.exigir_totp_supervisor(cfg.seguridad.db_path)


@pytest.mark.parametrize("ruta", ["/", "/clientes", "/conexiones", "/logs"])
def test_supervisor_obligado_solo_puede_ir_al_perfil(como_supervisor, cfg, ruta):
    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1")

    r = como_supervisor.get(ruta, follow_redirects=False)

    assert r.status_code == 303
    assert r.headers["location"] == "/perfil"


def test_la_politica_alcanza_a_las_sesiones_ya_abiertas(como_supervisor, cfg):
    """Imponerla no debe esperar a que caduquen las sesiones en curso"""
    assert como_supervisor.get("/", follow_redirects=False).status_code == 200

    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1")

    assert como_supervisor.get("/", follow_redirects=False).status_code == 303


def test_el_supervisor_obligado_recupera_el_panel_al_activarlo(como_supervisor, cfg, usuarios):
    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1")
    assert como_supervisor.get("/", follow_redirects=False).status_code == 303

    dar_de_alta(como_supervisor, cfg, usuarios["supervisor"])

    assert como_supervisor.get("/", follow_redirects=False).status_code == 200


def test_el_obligado_no_puede_desactivarlo(como_supervisor, cfg, usuarios):
    dar_de_alta(como_supervisor, cfg, usuarios["supervisor"])
    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1")

    r = como_supervisor.post(
        "/perfil/totp/desactivar", headers={"X-CSRF-Token": csrf_de(como_supervisor, cfg)}
    )

    assert "no puedes desactivarlo" in r.text.lower()
    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["supervisor"])["totp_activado"]


def test_el_admin_si_puede_desactivar_el_suyo(como_admin, cfg, usuarios):
    dar_de_alta(como_admin, cfg, usuarios["admin"])

    como_admin.post(
        "/perfil/totp/desactivar", headers={"X-CSRF-Token": csrf_de(como_admin, cfg)}
    )

    registro = db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])
    assert not registro["totp_activado"]
    assert registro["totp_secret"] is None, "el secreto debe borrarse, no quedar huérfano"


# ------------------------------------------------------------ restablecimiento

def test_el_admin_restablece_el_de_otro(como_admin, otro_cliente, cfg, usuarios):
    supervisor = entrar(otro_cliente, usuarios["supervisor"], PASSWORD_SUPERVISOR)
    dar_de_alta(supervisor, cfg, usuarios["supervisor"])

    r = como_admin.post(
        "/admin/usuarios/%s/totp/restablecer" % usuarios["supervisor"],
        headers={"X-CSRF-Token": csrf_de(como_admin, cfg)},
    )

    assert r.status_code == 200, r.text
    assert not db.obtener_usuario(cfg.seguridad.db_path, usuarios["supervisor"])["totp_activado"]


def test_restablecer_cierra_las_sesiones_de_esa_cuenta(como_admin, otro_cliente, cfg, usuarios):
    """
    Si el segundo factor estaba comprometido, las sesiones abiertas con él
    también lo están.
    """
    supervisor = entrar(otro_cliente, usuarios["supervisor"], PASSWORD_SUPERVISOR)
    dar_de_alta(supervisor, cfg, usuarios["supervisor"])
    assert supervisor.get("/", follow_redirects=False).status_code == 200

    como_admin.post(
        "/admin/usuarios/%s/totp/restablecer" % usuarios["supervisor"],
        headers={"X-CSRF-Token": csrf_de(como_admin, cfg)},
    )

    assert supervisor.get("/", follow_redirects=False).status_code == 303


def test_el_supervisor_no_puede_restablecer_a_nadie(como_supervisor, cfg, usuarios):
    r = como_supervisor.post(
        "/admin/usuarios/%s/totp/restablecer" % usuarios["admin"],
        headers={"X-CSRF-Token": csrf_de(como_supervisor, cfg)},
    )
    assert r.status_code == 403


def test_restablecer_queda_auditado(como_admin, otro_cliente, cfg, usuarios):
    supervisor = entrar(otro_cliente, usuarios["supervisor"], PASSWORD_SUPERVISOR)
    dar_de_alta(supervisor, cfg, usuarios["supervisor"])

    como_admin.post(
        "/admin/usuarios/%s/totp/restablecer" % usuarios["supervisor"],
        headers={"X-CSRF-Token": csrf_de(como_admin, cfg)},
    )

    acciones = [e["accion"] for e in db.listar_auditoria(cfg.seguridad.db_path)]
    assert "totp_restablecer" in acciones


# ------------------------------------------------------------------ migración

def test_una_base_antigua_se_migra_sola(tmp_path):
    """
    Las instalaciones existentes tienen la tabla sin las columnas del TOTP.
    CREATE TABLE IF NOT EXISTS no las añade: hay que ampliarlas al arrancar.
    """
    ruta = base_de_dos_roles(tmp_path, [("antiguo", "admin")])

    db.init_db(ruta)

    registro = db.obtener_usuario(ruta, "antiguo")
    assert registro["totp_activado"] == 0
    assert registro["totp_secret"] is None


# --------------------------------- no pisar un alta que ya está en curso

def test_volver_a_pulsar_activar_no_genera_otro_secreto(como_admin, csrf_admin, cfg):
    """
    El fallo: el secreto solo se enseña una vez, así que al recargar la página
    reaparecía el botón de activar. Pulsarlo generaba un secreto nuevo y dejaba
    muerta la cuenta que el usuario ya había guardado en el móvil, sin que nada
    lo explicara.
    """
    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})
    primero = db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"]

    respuesta = como_admin.post("/perfil/totp/iniciar",
                                headers={"X-CSRF-Token": csrf_admin})
    segundo = db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"]

    assert segundo == primero, "el segundo clic no puede pisar el alta en curso"
    assert "alta en curso" in respuesta.text


def test_el_codigo_del_alta_original_sigue_valiendo(como_admin, csrf_admin, cfg):
    """La consecuencia que importa: lo escaneado antes tiene que seguir sirviendo"""
    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})
    secreto = db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"]

    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})

    respuesta = como_admin.post(
        "/perfil/totp/confirmar",
        data={"codigo": totp.codigo(secreto)},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_activado"]


def test_al_recargar_no_reaparece_el_boton_de_activar(como_admin, csrf_admin):
    """Con un alta a medias hay que ver el formulario de confirmar, no el botón"""
    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})

    texto = como_admin.get("/perfil").text

    assert "Activar verificación en dos pasos" not in texto
    assert "alta a medias" in texto
    assert "Descartar y empezar de nuevo" in texto


def test_descartar_permite_empezar_de_nuevo(como_admin, csrf_admin, cfg):
    """La salida para quien perdió la clave, pero como acto deliberado"""
    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})
    primero = db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"]

    como_admin.post("/perfil/totp/descartar", headers={"X-CSRF-Token": csrf_admin})
    assert db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"] is None

    como_admin.post("/perfil/totp/iniciar", headers={"X-CSRF-Token": csrf_admin})
    segundo = db.obtener_usuario(cfg.seguridad.db_path, "jefa")["totp_secret"]

    assert segundo and segundo != primero


def test_descartar_sin_alta_en_curso_lo_dice(como_admin, csrf_admin):
    respuesta = como_admin.post("/perfil/totp/descartar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert "No hay ningún alta en curso" in respuesta.text
