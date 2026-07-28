"""
La jerarquía de tres roles: quién es superusuario y quién puede tocar a quién.

Lo que se vigila aquí es el blindaje. Un admin que pudiera cambiarle la
contraseña al superusuario sería superusuario en dos pasos, así que no basta
con que no le cambie el rol: hay que cerrar también la contraseña, el segundo
factor, la desactivación y el borrado.
"""

import sqlite3

import pytest

from app import db
from app.routers.administracion import _ultimo_al_mando

from .conftest import PASSWORD_SUPER, base_de_dos_roles


# ------------------------------------------------------- el primero manda

@pytest.fixture
def base_vacia(cfg):
    """Instalación recién hecha: esquema puesto y ni una cuenta"""
    db.init_db(cfg.seguridad.db_path)
    return cfg.seguridad.db_path


def test_la_primera_cuenta_nace_superusuario(base_vacia):
    """Se pida el rol que se pida: no hay otra forma de tener superusuario"""
    _, concedido = db.crear_usuario(base_vacia, "primera", "contrasena-larga-1", "supervisor")

    assert concedido == "superusuario"
    assert db.obtener_usuario(base_vacia, "primera")["rol"] == "superusuario"


def test_la_segunda_cuenta_ya_no(base_vacia):
    db.crear_usuario(base_vacia, "primera", "contrasena-larga-1", "admin")
    _, concedido = db.crear_usuario(base_vacia, "segunda", "contrasena-larga-2", "admin")

    assert concedido == "admin"


def test_el_rol_de_superusuario_no_se_puede_pedir(base_vacia):
    with pytest.raises(ValueError, match="Rol no válido"):
        db.crear_usuario(base_vacia, "listillo", "contrasena-larga-1", "superusuario")


def test_la_base_no_admite_dos_superusuarios(cfg, usuarios):
    """
    El índice parcial es lo que sigue siendo cierto si el código falla.

    Se salta cambiar_rol a propósito y se escribe en la tabla directamente:
    esta prueba es sobre la base, no sobre la capa de encima.
    """
    with pytest.raises(sqlite3.IntegrityError):
        with db.conexion(cfg.seguridad.db_path) as con:
            con.execute("UPDATE usuarios SET rol = 'superusuario' WHERE usuario = ?",
                        (usuarios["admin"],))


def test_cambiar_rol_no_concede_ni_quita_el_de_superusuario(cfg, usuarios):
    ruta = cfg.seguridad.db_path

    with pytest.raises(ValueError, match="Rol no válido"):
        db.cambiar_rol(ruta, usuarios["admin"], "superusuario")

    # Y al revés: aunque el rol pedido sea válido, el WHERE excluye al super
    db.cambiar_rol(ruta, usuarios["super"], "supervisor")
    assert db.obtener_usuario(ruta, usuarios["super"])["rol"] == "superusuario"


# ------------------------------------------------------ nadie se cambia solo

def test_nadie_cambia_su_propio_rol(como_admin, csrf_admin, cfg, usuarios):
    """
    Era el fallo: 'jefa' podía degradarse a sí misma y quedarse fuera de la
    única página donde arreglarlo.
    """
    respuesta = como_admin.post(
        "/admin/usuarios/%s/rol" % usuarios["admin"],
        data={"rol": "supervisor"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 400
    assert "tu propio rol" in respuesta.text
    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["rol"] == "admin"


def test_el_superusuario_tampoco_cambia_el_suyo(como_super, csrf_super, cfg, usuarios):
    respuesta = como_super.post(
        "/admin/usuarios/%s/rol" % usuarios["super"],
        data={"rol": "admin"},
        headers={"X-CSRF-Token": csrf_super},
    )

    assert respuesta.status_code == 400
    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["super"])["rol"] == "superusuario"


def test_la_tabla_no_ofrece_cambiar_el_rol_propio(como_admin, usuarios):
    """Lo que el servidor rechaza, la interfaz no debe llegar a ofrecerlo"""
    html = como_admin.get("/admin/usuarios/tabla").text

    assert 'hx-post="/admin/usuarios/%s/rol"' % usuarios["admin"] not in html
    assert 'hx-post="/admin/usuarios/%s/rol"' % usuarios["supervisor"] in html


# --------------------------------------- pulsar sin cambiar no echa a nadie

def test_cambiar_al_mismo_rol_no_cierra_la_sesion(como_admin, csrf_admin, cfg, usuarios):
    """
    Era el otro fallo: el botón cerraba la sesión de la cuenta de destino
    aunque el rol fuese el mismo, porque borraba sesiones sin mirar.
    """
    respuesta = como_admin.post(
        "/admin/usuarios/%s/rol" % usuarios["supervisor"],
        data={"rol": "supervisor"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert "no se ha cambiado nada" in respuesta.text


def test_pulsar_sin_cambiar_no_echa_al_destinatario(app, como_admin, csrf_admin, cfg, usuarios):
    """La sesión de la cuenta afectada tiene que seguir viva"""
    from fastapi.testclient import TestClient

    from .conftest import PASSWORD_SUPERVISOR, _entrar

    with TestClient(app) as otro:
        _entrar(otro, usuarios["supervisor"], PASSWORD_SUPERVISOR)
        assert otro.get("/", follow_redirects=False).status_code == 200

        como_admin.post(
            "/admin/usuarios/%s/rol" % usuarios["supervisor"],
            data={"rol": "supervisor"},
            headers={"X-CSRF-Token": csrf_admin},
        )

        assert otro.get("/", follow_redirects=False).status_code == 200


def test_un_cambio_de_verdad_si_cierra_la_sesion(app, como_admin, csrf_admin, cfg, usuarios):
    from fastapi.testclient import TestClient

    from .conftest import PASSWORD_SUPERVISOR, _entrar

    with TestClient(app) as otro:
        _entrar(otro, usuarios["supervisor"], PASSWORD_SUPERVISOR)

        como_admin.post(
            "/admin/usuarios/%s/rol" % usuarios["supervisor"],
            data={"rol": "admin"},
            headers={"X-CSRF-Token": csrf_admin},
        )

        assert otro.get("/", follow_redirects=False).status_code == 303


# --------------------------------------------------- el superusuario blindado

RUTAS_CONTRA_EL_SUPER = [
    ("rol", {"rol": "supervisor"}),
    ("password", {"password": "contrasena-secuestrada"}),
    ("activo", {"activo": 0}),
    ("borrar", {}),
    ("totp/restablecer", {}),
]


@pytest.mark.parametrize("accion,datos", RUTAS_CONTRA_EL_SUPER)
def test_un_admin_no_toca_al_superusuario(como_admin, csrf_admin, cfg, usuarios, accion, datos):
    respuesta = como_admin.post(
        "/admin/usuarios/%s/%s" % (usuarios["super"], accion),
        data=datos,
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 400, respuesta.text
    assert "superusuario" in respuesta.text

    registro = db.obtener_usuario(cfg.seguridad.db_path, usuarios["super"])
    assert registro["rol"] == "superusuario"
    assert registro["activo"] == 1


def test_el_intento_contra_el_superusuario_queda_auditado(como_admin, csrf_admin, cfg, usuarios):
    """No es una errata de formulario: es alguien probando a saltarse la jerarquía"""
    como_admin.post(
        "/admin/usuarios/%s/borrar" % usuarios["super"],
        headers={"X-CSRF-Token": csrf_admin},
    )

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    denegadas = [e for e in entradas if e["resultado"] == "denegada"]

    assert denegadas, "el intento debería constar"
    assert denegadas[0]["accion"] == "borrar_usuario_panel"
    assert denegadas[0]["objetivo"] == usuarios["super"]


def test_el_admin_no_le_cambia_la_contrasena_al_superusuario(como_admin, csrf_admin, cfg, usuarios):
    """
    Es la vía de escalada más corta: cambiarle la contraseña y entrar con ella.
    Se comprueba que además de rechazarlo, no la ha tocado.
    """
    antes = db.obtener_usuario(cfg.seguridad.db_path, usuarios["super"])["password_hash"]

    como_admin.post(
        "/admin/usuarios/%s/password" % usuarios["super"],
        data={"password": "contrasena-secuestrada"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["super"])["password_hash"] == antes
    assert db.verificar_password(cfg.seguridad.db_path, usuarios["super"], PASSWORD_SUPER)


def test_el_superusuario_si_se_cambia_su_propia_contrasena(como_super, csrf_super, cfg, usuarios):
    """Blindado contra los demás, no contra sí mismo: si no, no podría ni rotarla"""
    respuesta = como_super.post(
        "/admin/usuarios/%s/password" % usuarios["super"],
        data={"password": "contrasena-nueva-larga"},
        headers={"X-CSRF-Token": csrf_super},
    )

    assert respuesta.status_code == 200, respuesta.text
    assert db.verificar_password(cfg.seguridad.db_path, usuarios["super"], "contrasena-nueva-larga")


def test_la_tabla_no_ofrece_acciones_contra_el_superusuario(como_admin, usuarios):
    html = como_admin.get("/admin/usuarios/tabla").text

    assert "Cuenta blindada" in html
    for accion in ("rol", "password", "activo", "borrar"):
        assert 'hx-post="/admin/usuarios/%s/%s"' % (usuarios["super"], accion) not in html


# ------------------------------------------------- botón visible solo al cambiar

def test_la_opcion_vigente_va_marcada_para_el_css(como_admin, usuarios):
    """
    El botón se esconde con :has(option[data-actual]:checked), así que la marca
    tiene que ir en la opción del rol que la cuenta tiene ahora mismo, y en esa
    sola. Si acabara en las dos, o en ninguna, el botón no volvería a aparecer.
    """
    # La plantilla parte las opciones en varias líneas para que se lean; al
    # navegador le da igual y a esta comprobación también.
    html = " ".join(como_admin.get("/admin/usuarios/tabla").text.split())

    assert 'class="en-linea cambio-rol"' in html
    # 'mirona' es supervisor: la marca va en su opción de supervisor
    assert 'data-actual selected>supervisor</option>' in html
    assert html.count("data-actual") == 1, "solo la fila de 'mirona' ofrece cambiar el rol"


# ------------------------------------------- el guardián del último al mando

def test_ultimo_al_mando_solo_cuenta_a_los_activos(cfg, usuarios):
    """
    Por ruta no se alcanza —quien actúa ya es mando activo y no puede
    apuntarse a sí mismo, así que siempre son dos— pero la condición tiene que
    ser correcta igualmente: un admin desactivado no resta a nadie del mando, y
    bloquear su borrado por eso era un falso positivo.
    """
    ruta = cfg.seguridad.db_path
    db.borrar_usuario(ruta, usuarios["super"])
    db.cambiar_rol(ruta, usuarios["supervisor"], "admin")
    db.activar_usuario(ruta, usuarios["supervisor"], False)

    assert db.contar_mando_activo(ruta) == 1

    inactivo = db.obtener_usuario(ruta, usuarios["supervisor"])
    activo = db.obtener_usuario(ruta, usuarios["admin"])

    assert not _ultimo_al_mando(ruta, inactivo), "un admin desactivado no sostiene el panel"
    assert _ultimo_al_mando(ruta, activo)


def test_el_superusuario_cuenta_como_mando(cfg, usuarios):
    """Manda igual que un admin: si no contara, el guardián daría un falso positivo"""
    ruta = cfg.seguridad.db_path
    db.cambiar_rol(ruta, usuarios["admin"], "supervisor")

    assert db.contar_mando_activo(ruta) == 1


# --------------------------------------- lo que cada rol ve en la interfaz
#
# Un rol nuevo no puede obligar a acordarse de cuatro plantillas. Al añadir
# 'superusuario' se quedaron cuatro sitios comparando con la cadena 'admin', y
# la cuenta con más poder del panel perdió el menú de Usuarios, el formulario de
# crear clientes y los botones de la tabla. Las rutas respondían 200: el fallo
# estaba solo en lo que se dibujaba.

def test_ninguna_plantilla_compara_el_rol_de_la_sesion():
    """
    La pregunta es '¿manda?', y la responde db.ROLES_MANDO en un solo sitio.
    Comparar `sesion.rol` con una cadena reparte esa decisión por las
    plantillas, y ahí es donde se olvida al añadir un rol.

    Ojo: `u.rol` sí puede compararse — habla de la cuenta de cada fila, no de
    quien mira.
    """
    import re
    from pathlib import Path

    plantillas = Path(__file__).resolve().parents[1] / "app" / "templates"
    culpables = []

    for archivo in plantillas.rglob("*.html"):
        for n, linea in enumerate(archivo.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"sesion\.rol\s*[=!]=", linea):
                culpables.append("%s:%d" % (archivo.name, n))

    assert not culpables, (
        "Comparan el rol de la sesión en vez de usar 'manda': %s" % ", ".join(culpables)
    )


@pytest.mark.parametrize("ruta,marca", [
    ("/", 'href="/admin/usuarios"'),
    ("/clientes", "Crear cliente"),
])
def test_el_superusuario_ve_lo_mismo_que_un_admin(como_admin, app, usuarios, ruta, marca):
    """
    No basta con que la ruta responda 200: tiene que dibujar los controles.

    El superusuario entra por un cliente aparte porque 'como_admin' y
    'como_super' comparten el mismo TestClient y pedir los dos deja solo la
    sesión del último.
    """
    from fastapi.testclient import TestClient

    from .conftest import PASSWORD_SUPER, _entrar

    assert marca in como_admin.get(ruta).text, "el admin debería verlo (control de la prueba)"

    with TestClient(app) as otro:
        _entrar(otro, usuarios["super"], PASSWORD_SUPER)
        assert marca in otro.get(ruta).text, (
            "el superusuario no ve %r en %s" % (marca, ruta)
        )


def test_el_supervisor_no_ve_esos_controles(como_supervisor):
    html = como_supervisor.get("/").text

    assert 'href="/admin/usuarios"' not in html
    assert 'href="/configuracion"' not in html


# ------------------------------------------------------ ventana de configuración

def test_el_supervisor_no_entra_en_configuracion(como_supervisor):
    """
    Enseña rutas de la PKI, del log y el puerto del management: es el plano de
    la instalación, no el estado de la VPN.
    """
    assert como_supervisor.get("/configuracion", follow_redirects=False).status_code == 403


@pytest.mark.parametrize("quien", ["como_admin", "como_super"])
def test_quien_manda_si_entra_en_configuracion(request, quien):
    cliente = request.getfixturevalue(quien)
    assert cliente.get("/configuracion").status_code == 200


# ------------------------------------------------- migración de una base viva

def test_una_base_de_dos_roles_se_convierte_en_tres(tmp_path):
    """
    Lo que decide si una instalación en marcha sobrevive a la actualización.

    El CHECK viejo solo admite 'admin' y 'lector', y SQLite no sabe alterarlo:
    si la reconstrucción falla, el panel arranca y no deja crear a nadie.
    """
    ruta = base_de_dos_roles(tmp_path, [
        ("primera", "admin"),
        ("segunda", "admin"),
        ("mirona", "lector"),
    ])

    db.init_db(ruta)

    assert db.obtener_usuario(ruta, "primera")["rol"] == "superusuario"
    assert db.obtener_usuario(ruta, "segunda")["rol"] == "admin"
    assert db.obtener_usuario(ruta, "mirona")["rol"] == "supervisor"


def test_la_migracion_asciende_al_admin_mas_antiguo_no_al_id_1(tmp_path):
    """
    Si la cuenta más vieja fuera un lector, ascenderla sería regalarle el mando
    de la instalación a quien solo miraba.
    """
    ruta = base_de_dos_roles(tmp_path, [
        ("mirona", "lector"),
        ("jefa", "admin"),
    ])

    db.init_db(ruta)

    assert db.obtener_usuario(ruta, "mirona")["rol"] == "supervisor"
    assert db.obtener_usuario(ruta, "jefa")["rol"] == "superusuario"


def test_una_base_sin_admins_se_queda_sin_superusuario(tmp_path):
    """
    No había a quién ascender, así que no se asciende a nadie. Es preferible a
    inventarse un superusuario entre las cuentas de solo lectura.
    """
    ruta = base_de_dos_roles(tmp_path, [("mirona", "lector")])

    db.init_db(ruta)

    assert db.obtener_usuario(ruta, "mirona")["rol"] == "supervisor"

    # Y no es un callejón sin salida: la CLI puede designar uno
    db.designar_superusuario(ruta, "mirona")
    assert db.obtener_usuario(ruta, "mirona")["rol"] == "superusuario"


# --------------------------------------------- designar desde el servidor

def test_designar_superusuario_baja_al_anterior(cfg, usuarios):
    """El índice único solo admite uno: hay que bajar al que había"""
    ruta = cfg.seguridad.db_path

    _, anterior = db.designar_superusuario(ruta, usuarios["admin"])

    assert anterior == usuarios["super"]
    assert db.obtener_usuario(ruta, usuarios["admin"])["rol"] == "superusuario"
    assert db.obtener_usuario(ruta, usuarios["super"])["rol"] == "admin"


def test_designar_a_quien_ya_lo_es_no_hace_nada(cfg, usuarios):
    with pytest.raises(ValueError, match="ya es el superusuario"):
        db.designar_superusuario(cfg.seguridad.db_path, usuarios["super"])


def test_designar_a_alguien_que_no_existe(cfg, usuarios):
    with pytest.raises(ValueError, match="No existe"):
        db.designar_superusuario(cfg.seguridad.db_path, "fantasma")


def test_designar_puede_ascender_a_un_supervisor(cfg, usuarios):
    """
    No se comprueba el rol de destino a propósito: quien ejecuta esto está
    dentro del servidor, que es más autoridad que cualquier rol del panel.
    """
    ruta = cfg.seguridad.db_path

    db.designar_superusuario(ruta, usuarios["supervisor"])

    assert db.obtener_usuario(ruta, usuarios["supervisor"])["rol"] == "superusuario"


def test_el_panel_no_tiene_ninguna_via_para_designar(como_admin, csrf_admin, usuarios, cfg):
    """
    Lo que hace la CLI no debe existir por HTTP: el superusuario es fijo desde
    el panel, y esa es toda la garantía de que no se lo pueda quitar nadie.
    """
    respuesta = como_admin.post(
        "/admin/usuarios/%s/rol" % usuarios["admin"],
        data={"rol": "superusuario"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 400
    assert db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["rol"] == "admin"


def test_la_migracion_conserva_la_politica_de_totp(tmp_path):
    """El ajuste cambió de nombre; lo que decidió el administrador no cambia"""
    ruta = base_de_dos_roles(
        tmp_path,
        [("jefa", "admin")],
        ajustes={"exigir_totp_lector": "1"},
    )

    db.init_db(ruta)

    assert db.exigir_totp_supervisor(ruta)


def test_la_migracion_no_reescribe_la_auditoria(tmp_path):
    """
    La auditoría es el registro de lo que pasó, y lo que pasó se llamaba
    'lector'. Retocarla para que cuadre con los nombres de hoy sería falsearla.
    """
    ruta = base_de_dos_roles(tmp_path, [("jefa", "admin")])
    db.init_db(ruta)
    db.registrar(ruta, "jefa", "politica_totp_lector", "lector", detalle="exigido")

    db.init_db(ruta)  # segundo arranque: ya no migra, pero por si acaso

    entrada = db.listar_auditoria(ruta)[0]
    assert entrada["accion"] == "politica_totp_lector"
    assert entrada["objetivo"] == "lector"


def test_migrar_dos_veces_no_rompe_nada(tmp_path):
    """init_db corre en cada arranque: la segunda vez no debe tocar nada"""
    ruta = base_de_dos_roles(tmp_path, [("jefa", "admin"), ("mirona", "lector")])

    db.init_db(ruta)
    db.init_db(ruta)

    assert db.obtener_usuario(ruta, "jefa")["rol"] == "superusuario"
    assert db.obtener_usuario(ruta, "mirona")["rol"] == "supervisor"


def test_la_migracion_deja_las_claves_foraneas_sanas(tmp_path):
    """
    Reconstruir la tabla con las claves foráneas puestas reescribiría las
    referencias de sesiones para que apuntaran a la tabla temporal. Se apagan
    a propósito, y esto comprueba que se vuelven a encender enteras.
    """
    ruta = base_de_dos_roles(tmp_path, [("jefa", "admin")])

    db.init_db(ruta)

    with db.conexion(ruta) as con:
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        destino = con.execute(
            "SELECT \"table\" FROM pragma_foreign_key_list('sesiones')"
        ).fetchone()[0]

    assert destino == "usuarios", "la referencia debe seguir apuntando a usuarios"


def test_despues_de_migrar_se_puede_crear_gente(tmp_path):
    """El CHECK nuevo tiene que admitir los roles nuevos de verdad"""
    ruta = base_de_dos_roles(tmp_path, [("jefa", "admin")])
    db.init_db(ruta)

    _, rol = db.crear_usuario(ruta, "nueva", "contrasena-larga-1", "supervisor")

    assert rol == "supervisor", "la base ya no estaba vacía"
    assert db.obtener_usuario(ruta, "nueva")["rol"] == "supervisor"
