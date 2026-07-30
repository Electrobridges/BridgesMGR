"""
Perfiles pendientes de repartir.

Hay operaciones que invalidan de golpe todos los .ovpn ya entregados —rotar la
clave tls-crypt, reconstruir la CA— y dejan al administrador con N archivos que
repartir y ninguna forma de acordarse. El aviso vive en el servidor y aguanta
hasta que alguien lo da por cerrado: uno que se fuera al recargar no serviría.
"""

import pytest

from app import db


def test_abrir_y_leer(cfg, usuarios):
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_TLS_CRYPT,
                     ["daniel", "portatil.oficina"])

    reparto = db.reparto_abierto(cfg.seguridad.db_path)

    assert reparto["motivo"] == db.MOTIVO_TLS_CRYPT
    assert [c["cn"] for c in reparto["clientes"]] == ["daniel", "portatil.oficina"]
    assert reparto["pendientes"] == 2


def test_sin_reparto_no_hay_aviso(cfg, usuarios):
    assert db.reparto_abierto(cfg.seguridad.db_path) is None


def test_motivo_desconocido_se_rechaza(cfg, usuarios):
    """Cadena fija y no texto libre: la plantilla decide el mensaje desde esto"""
    with pytest.raises(ValueError):
        db.abrir_reparto(cfg.seguridad.db_path, "porque-si", ["daniel"])


def test_abrir_uno_nuevo_cierra_el_anterior(cfg, usuarios):
    """
    Dos avisos a la vez solo confunden, y el último manda: los perfiles del
    reparto anterior también dejaron de servir.
    """
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_TLS_CRYPT, ["viejo"])
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["nuevo"])

    reparto = db.reparto_abierto(cfg.seguridad.db_path)
    assert reparto["motivo"] == db.MOTIVO_CA
    assert [c["cn"] for c in reparto["clientes"]] == ["nuevo"]


def test_marcar_descargado(cfg, usuarios):
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel", "otro"])
    db.marcar_descargado(cfg.seguridad.db_path, "daniel")

    reparto = db.reparto_abierto(cfg.seguridad.db_path)
    hecho = {c["cn"]: bool(c["descargado"]) for c in reparto["clientes"]}

    assert hecho == {"daniel": True, "otro": False}
    assert reparto["pendientes"] == 1


def test_marcar_un_cn_de_fuera_no_hace_nada(cfg, usuarios):
    """Descargar un perfil cualquiera es lo normal y no debe tocar el reparto"""
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel"])
    db.marcar_descargado(cfg.seguridad.db_path, "ajeno")

    assert db.reparto_abierto(cfg.seguridad.db_path)["pendientes"] == 1


def test_cerrar_solo_funciona_una_vez(cfg, usuarios):
    """
    Dos pestañas, o el botón pulsado dos veces. La segunda no puede devolver
    éxito o la auditoría acabaría con un registro de algo que no ocurrió.
    """
    rid = db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel"])

    assert db.cerrar_reparto(cfg.seguridad.db_path, rid, "danieladm") is True
    assert db.cerrar_reparto(cfg.seguridad.db_path, rid, "danieladm") is False
    assert db.reparto_abierto(cfg.seguridad.db_path) is None


# ------------------------------------------------------------ por la web

@pytest.fixture
def helper_falso(monkeypatch):
    """Lo mínimo para que la página de clientes se pinte"""
    from app.core import easyrsa

    monkeypatch.setattr(easyrsa, "listar_certificados",
                        lambda c: {"validos": ["daniel"], "revocados": []})
    monkeypatch.setattr(easyrsa, "generar_ovpn", lambda c, cn: "client\n")

    import app.routers.clientes as rc
    monkeypatch.setattr(rc.easyrsa, "listar_certificados",
                        lambda c: {"validos": ["daniel"], "revocados": []})
    monkeypatch.setattr(rc.easyrsa, "generar_ovpn", lambda c, cn: "client\n")


def test_la_pagina_muestra_el_aviso(como_admin, helper_falso, cfg):
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_TLS_CRYPT, ["daniel"])

    texto = como_admin.get("/clientes").text

    assert "pendientes de repartir" in texto
    assert "tls-crypt" in texto


def test_sin_reparto_la_banda_queda_vacia(como_admin, helper_falso):
    """El div existe siempre: HTMX necesita algo con ese id a lo que apuntar"""
    texto = como_admin.get("/clientes").text

    assert 'id="aviso-reparto"' in texto
    assert "pendientes de repartir" not in texto


def test_descargar_marca_el_perfil(como_admin, helper_falso, cfg):
    db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel", "otro"])

    como_admin.get("/clientes/daniel/ovpn")

    assert db.reparto_abierto(cfg.seguridad.db_path)["pendientes"] == 1


def test_aceptar_cierra_y_audita(como_admin, csrf_admin, helper_falso, cfg):
    rid = db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel"])

    respuesta = como_admin.post("/clientes/reparto/%d/aceptar" % rid,
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    assert "hx-swap-oob" in respuesta.text
    assert db.reparto_abierto(cfg.seguridad.db_path) is None

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "cerrar_reparto" for e in entradas)


def test_aceptar_avisa_de_los_que_faltan(como_admin, csrf_admin, helper_falso, cfg):
    """
    Cerrar con perfiles sin descargar no se impide, pero se dice.

    Quien lo cierra puede haberlos repartido por otra vía; lo que no puede es
    hacerlo sin enterarse de que quedaban.
    """
    rid = db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["a", "b", "c"])

    respuesta = como_admin.post("/clientes/reparto/%d/aceptar" % rid,
                                headers={"X-CSRF-Token": csrf_admin})

    assert "3 perfiles sin descargar" in respuesta.text


def test_un_supervisor_no_puede_cerrarlo(como_supervisor, csrf_supervisor,
                                         helper_falso, cfg):
    rid = db.abrir_reparto(cfg.seguridad.db_path, db.MOTIVO_CA, ["daniel"])

    respuesta = como_supervisor.post("/clientes/reparto/%d/aceptar" % rid,
                                     headers={"X-CSRF-Token": csrf_supervisor})

    assert respuesta.status_code == 403
    assert db.reparto_abierto(cfg.seguridad.db_path) is not None
