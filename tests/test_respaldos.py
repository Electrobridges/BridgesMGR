"""
Respaldos de la base del panel.

La pregunta que hay detrás de todo esto: qué sale del servidor. Un respaldo es
la base entera —hashes de contraseñas y secretos TOTP— así que se hace solo,
se rota solo, y no baja por HTTP.
"""

import gzip
import os
import sqlite3
from datetime import datetime

import pytest

from app import db, respaldar
from app.core import respaldos


@pytest.fixture
def base(tmp_path):
    """Una base del panel con algo dentro"""
    ruta = str(tmp_path / "panel.db")
    db.init_db(ruta)
    db.crear_usuario(ruta, "daniel", "contrasena-larga-de-prueba", "admin")
    db.registrar(ruta, usuario="daniel", accion="crear_cliente", objetivo="movil")
    return ruta


@pytest.fixture
def directorio(tmp_path):
    return str(tmp_path / "respaldos")


# ------------------------------------------------------- crear y leer copias

def test_el_respaldo_se_abre_como_una_base_de_verdad(base, directorio):
    """
    Lo único que demuestra que un respaldo sirve es abrirlo. Un archivo del
    tamaño esperado puede estar cortado por la mitad.
    """
    nombre = respaldos.crear(base, directorio)
    copia = os.path.join(directorio, "copia.db")

    with gzip.open(os.path.join(directorio, nombre), "rb") as entrada:
        with open(copia, "wb") as salida:
            salida.write(entrada.read())

    con = sqlite3.connect(copia)
    try:
        usuarios = con.execute("SELECT usuario FROM usuarios").fetchall()
        acciones = con.execute("SELECT accion FROM auditoria").fetchall()
    finally:
        con.close()

    assert [u[0] for u in usuarios] == ["daniel"]
    assert [a[0] for a in acciones] == ["crear_cliente"]


def test_el_respaldo_no_lo_puede_leer_nadie_mas(base, directorio):
    """Vale lo mismo que la base: mismos permisos que la base"""
    nombre = respaldos.crear(base, directorio)

    assert oct(os.stat(os.path.join(directorio, nombre)).st_mode)[-3:] == "600"
    assert oct(os.stat(directorio).st_mode)[-3:] == "700"


def test_se_respalda_con_la_base_en_uso(base, directorio):
    """
    El panel no se para para respaldar. La API de backup de sqlite3 copia un
    estado consistente: lo que otra conexión aún no ha confirmado no aparece,
    en vez de salir a medias como saldría con un cp.
    """
    otra = sqlite3.connect(base, isolation_level=None)
    try:
        otra.execute("BEGIN")
        otra.execute(
            "INSERT INTO auditoria (ts, usuario, accion, resultado)"
            " VALUES ('2026-01-01T00:00:00+00:00', 'x', 'a_medias', 'ok')"
        )

        nombre = respaldos.crear(base, directorio)
    finally:
        otra.rollback()
        otra.close()

    copia = os.path.join(directorio, "copia.db")
    with gzip.open(os.path.join(directorio, nombre), "rb") as e:
        with open(copia, "wb") as s:
            s.write(e.read())

    con = sqlite3.connect(copia)
    try:
        acciones = [a[0] for a in con.execute("SELECT accion FROM auditoria")]
    finally:
        con.close()

    assert "a_medias" not in acciones
    assert "crear_cliente" in acciones


def test_dos_respaldos_del_mismo_segundo_no_se_pisan(base, directorio):
    """
    Pulsar dos veces «Respaldar ahora» caía en el mismo segundo, así que el
    segundo archivo sobrescribía al primero: dos copias pedidas, una en disco.
    """
    momento = datetime(2026, 1, 1, 3, 0, 0)

    primero = respaldos.crear(base, directorio, momento)
    segundo = respaldos.crear(base, directorio, momento)

    assert primero != segundo
    assert len(respaldos.listar(directorio)) == 2
    # Y el más nuevo va primero, aunque por texto '-2' ordene antes que '.db'
    assert respaldos.listar(directorio)[0]["nombre"] == segundo


def test_listar_va_del_mas_reciente_al_mas_antiguo_y_pasa_de_lo_ajeno(base, directorio):
    for momento in (datetime(2026, 1, 1, 3), datetime(2026, 1, 2, 3), datetime(2026, 1, 3, 3)):
        respaldos.crear(base, directorio, momento)

    # Un archivo que no ha puesto el panel no cuenta como respaldo
    with open(os.path.join(directorio, "notas.txt"), "w") as f:
        f.write("nada")

    listado = [r["nombre"] for r in respaldos.listar(directorio)]

    assert listado == [
        "ovpn-web-20260103-030000.db.gz",
        "ovpn-web-20260102-030000.db.gz",
        "ovpn-web-20260101-030000.db.gz",
    ]


def test_listar_un_directorio_que_no_existe_no_es_un_error(tmp_path):
    """Todavía no se ha hecho ninguno; eso no es un fallo que contar"""
    assert respaldos.listar(str(tmp_path / "no-existe")) == []


def test_rotar_deja_las_mas_recientes(base, directorio):
    for dia in range(1, 6):
        respaldos.crear(base, directorio, datetime(2026, 1, dia, 3))

    borrados = respaldos.rotar(directorio, conservar=2)

    assert len(borrados) == 3
    assert [r["nombre"] for r in respaldos.listar(directorio)] == [
        "ovpn-web-20260105-030000.db.gz",
        "ovpn-web-20260104-030000.db.gz",
    ]


def test_rotar_con_cero_se_lee_como_no_rotar(base, directorio):
    """
    Un cero en el formulario significa 'no rotes', no 'bórralos todos'. Al
    revés, la primera vuelta del vigilante se llevaría el respaldo recién hecho.
    """
    respaldos.crear(base, directorio, datetime(2026, 1, 1, 3))

    assert respaldos.rotar(directorio, conservar=0) == []
    assert len(respaldos.listar(directorio)) == 1


@pytest.mark.parametrize("nombre", [
    "",
    "../../etc/passwd",
    "ovpn-web-20260101-030000.db.gz/../otro",
    "cualquier-cosa.db.gz",
    "ovpn-web-2026-01-01.db.gz",
])
def test_un_nombre_que_no_sea_el_suyo_no_toca_el_disco(directorio, nombre):
    """
    El nombre llega del formulario. os.path.join('/dir', '../..') sale del
    directorio sin quejarse, así que se comprueba la forma antes de borrar.
    """
    with pytest.raises(respaldos.ErrorRespaldo):
        respaldos.borrar(directorio, nombre)


def test_borrar_uno_que_ya_no_esta_lo_dice(base, directorio):
    respaldos.crear(base, directorio, datetime(2026, 1, 1, 3))

    assert respaldos.borrar(directorio, "ovpn-web-20260101-030000.db.gz") is True
    assert respaldos.borrar(directorio, "ovpn-web-20260101-030000.db.gz") is False


# ------------------------------------------------------------ la programación

def test_el_directorio_por_defecto_va_junto_a_la_base(cfg):
    esperado = os.path.join(os.path.dirname(cfg.seguridad.db_path), "respaldos")

    assert respaldar.directorio(cfg) == esperado


def test_un_directorio_configurado_manda(cfg):
    cfg.seguridad.respaldos_dir = "/var/respaldos/panel"

    assert respaldar.directorio(cfg) == "/var/respaldos/panel"


@pytest.mark.parametrize("frecuencia, hora, ultimo, ahora, esperado", [
    # Desactivado no respalda nunca, por muy vencido que esté
    (respaldar.DESACTIVADO, "03:00", datetime(2020, 1, 1), datetime(2026, 6, 1, 4), False),
    # Diario: nunca se ha hecho
    (respaldar.DIARIO, "03:00", None, datetime(2026, 6, 1, 4), True),
    # Diario: ya cruzó la hora de hoy y el último es de ayer
    (respaldar.DIARIO, "03:00", datetime(2026, 5, 31, 3, 1), datetime(2026, 6, 1, 4), True),
    # Diario: hoy ya se hizo
    (respaldar.DIARIO, "03:00", datetime(2026, 6, 1, 3, 1), datetime(2026, 6, 1, 4), False),
    # Diario: todavía no ha llegado la hora y lo de ayer está hecho
    (respaldar.DIARIO, "03:00", datetime(2026, 5, 31, 3, 1), datetime(2026, 6, 1, 2), False),
    # Semanal: cruzó la hora pero no han pasado siete días
    (respaldar.SEMANAL, "03:00", datetime(2026, 5, 28, 3, 1), datetime(2026, 6, 1, 4), False),
    # Semanal: cruzó la hora y han pasado siete días
    (respaldar.SEMANAL, "03:00", datetime(2026, 5, 20, 3, 1), datetime(2026, 6, 1, 4), True),
])
def test_cuando_toca_respaldar(frecuencia, hora, ultimo, ahora, esperado):
    assert respaldar.toca(frecuencia, hora, ultimo, ahora) is esperado


def test_si_el_panel_estuvo_parado_respalda_al_volver():
    """
    La hora programada pasó con el panel apagado. Al arrancar respalda en vez
    de esperar a la madrugada siguiente: si no, un servidor que se reinicia
    cada tarde no tendría ni una copia.
    """
    ultimo = datetime(2026, 6, 1, 3, 0)
    ahora = datetime(2026, 6, 2, 21, 0)   # la de las 03:00 de hoy se perdió

    assert respaldar.toca(respaldar.DIARIO, "03:00", ultimo, ahora) is True


@pytest.mark.parametrize("entrada, esperado", [
    ("03:00", "03:00"),
    ("3:5", "03:05"),
    ("25:00", respaldar.HORA_POR_DEFECTO),
    ("mañana", respaldar.HORA_POR_DEFECTO),
    ("", respaldar.HORA_POR_DEFECTO),
    (None, respaldar.HORA_POR_DEFECTO),
])
def test_la_hora_llega_de_un_formulario_y_se_sanea(base, entrada, esperado):
    puesto = respaldar.guardar_ajustes(base, respaldar.DIARIO, entrada, 7)

    assert puesto["hora"] == esperado


@pytest.mark.parametrize("entrada, esperado", [
    (7, 7), ("3", 3), (0, 1), (-5, 1), (10 ** 6, respaldar.MAX_CONSERVAR),
    ("muchas", respaldos.CONSERVAR_POR_DEFECTO),
])
def test_cuantas_conservar_tambien_se_sanea(base, entrada, esperado):
    puesto = respaldar.guardar_ajustes(base, respaldar.DIARIO, "03:00", entrada)

    assert puesto["conservar"] == esperado


def test_una_frecuencia_inventada_cae_en_desactivado(base):
    """Llega de un formulario: lo que no está en la lista no programa nada"""
    puesto = respaldar.guardar_ajustes(base, "cada-rato", "03:00", 7)

    assert puesto["frecuencia"] == respaldar.DESACTIVADO


def test_ejecutar_anota_cuando_fue_y_rota(cfg):
    db.init_db(cfg.seguridad.db_path)
    respaldar.guardar_ajustes(cfg.seguridad.db_path, respaldar.DIARIO, "03:00", 2)

    for dia in (1, 2, 3):
        respaldar.ejecutar(cfg, datetime(2026, 6, dia, 3))

    assert len(respaldos.listar(respaldar.directorio(cfg))) == 2
    assert respaldar.ajustes(cfg.seguridad.db_path)["ultimo"]


def test_el_vigilante_no_repite_el_respaldo_del_dia(cfg):
    """revisar() se llama cada cinco minutos: no puede copiar en cada vuelta"""
    db.init_db(cfg.seguridad.db_path)
    respaldar.guardar_ajustes(cfg.seguridad.db_path, respaldar.DIARIO, "03:00", 7)

    primero = respaldar.revisar(cfg, datetime.now())
    segundo = respaldar.revisar(cfg, datetime.now())

    assert primero is not None
    assert segundo is None


# ---------------------------------------------------------- desde el panel

def test_programar_el_respaldo_desde_la_web(como_admin, csrf_admin, cfg):
    respuesta = como_admin.post(
        "/configuracion/respaldos",
        data={"frecuencia": "diario", "hora": "04:30", "conservar": "5"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    puesto = respaldar.ajustes(cfg.seguridad.db_path)
    assert (puesto["frecuencia"], puesto["hora"], puesto["conservar"]) == ("diario", "04:30", 5)

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "ajustar_respaldos" for e in entradas)


def test_respaldar_ahora_deja_el_archivo_y_lo_ensena(como_admin, csrf_admin, cfg):
    respuesta = como_admin.post("/configuracion/respaldos/ahora",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    copias = respaldos.listar(respaldar.directorio(cfg))
    assert len(copias) == 1

    tabla = como_admin.get("/configuracion/respaldos/tabla").text
    assert copias[0]["nombre"] in tabla


def test_borrar_un_respaldo_inventado_no_sale_del_directorio(como_admin, csrf_admin, cfg):
    respuesta = como_admin.post(
        "/configuracion/respaldos/borrar",
        data={"nombre": "../../../etc/passwd"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 400
    assert "no válido" in respuesta.text
    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "borrar_respaldo" and e["resultado"] == "error"
               for e in entradas)


def _rutas_get(app):
    """
    Los caminos GET de la aplicación, bajando a los routers incluidos.

    FastAPI no deja las rutas de un include_router colgando de app.routes: las
    envuelve, y hay que pasar por original_router para verlas.
    """
    pendientes = list(app.routes)
    caminos = []

    while pendientes:
        elemento = pendientes.pop()
        interior = getattr(elemento, "original_router", None)
        if interior is not None:
            pendientes.extend(interior.routes)
            continue

        camino = getattr(elemento, "path", None)
        if camino and "GET" in (getattr(elemento, "methods", None) or set()):
            caminos.append(camino)

    return caminos


def test_los_respaldos_no_se_descargan_desde_la_web(app):
    """
    La regla que sostiene todo esto: un respaldo es la base entera —hashes y
    secretos TOTP— y no sale por HTTP. Si alguien añade la ruta de descarga
    'por comodidad', esto se pone rojo.
    """
    de_respaldos = [c for c in _rutas_get(app) if "respaldo" in c]

    assert de_respaldos == ["/configuracion/respaldos/tabla"]


def test_la_prueba_de_arriba_ve_las_rutas_de_verdad(app):
    """
    Una prueba que recorre rutas y no encuentra ninguna pasa siempre. Esta
    comprueba que el recorrido funciona, para que aquella signifique algo.
    """
    caminos = _rutas_get(app)

    assert "/configuracion" in caminos
    assert "/conexiones" in caminos


def test_un_supervisor_no_respalda(como_supervisor, csrf_supervisor):
    """Los respaldos viven en Configuración, que un supervisor no pisa"""
    assert como_supervisor.post(
        "/configuracion/respaldos/ahora",
        headers={"X-CSRF-Token": csrf_supervisor},
    ).status_code == 403
