"""
Histórico de perfiles eliminados.

«Eliminar» retira el perfil de la lista activa y NO lo borra de la PKI. No es
una limitación: la CRL se regenera desde index.txt cada vez que se revoca algo,
así que quitar de ahí la línea de un certificado le devolvería la validez en la
siguiente regeneración, y en silencio. Archivado sigue revocado y bloqueado.

Borrarlos de verdad solo será seguro tras reconstruir la CA, cuando queden
firmados por una autoridad que ya no existe y no haya nada que bloquear.
"""

import pytest

from app import db
from app.core import easyrsa


@pytest.fixture
def helper_falso(monkeypatch):
    estado = {"validos": ["daniel", "portatil.oficina"], "revocados": ["antiguo-becario"]}

    def listar(cfg):
        return {"validos": list(estado["validos"]), "revocados": list(estado["revocados"])}

    monkeypatch.setattr(easyrsa, "listar_certificados", listar)
    import app.routers.clientes as rc
    monkeypatch.setattr(rc.easyrsa, "listar_certificados", listar)
    return estado


# ------------------------------------------------------------ la base

def test_archivar_y_listar(cfg, usuarios):
    db.archivar_cliente(cfg.seguridad.db_path, "antiguo-becario", "danieladm")

    archivados = db.listar_archivados(cfg.seguridad.db_path)
    assert [a["cn"] for a in archivados] == ["antiguo-becario"]
    assert archivados[0]["por"] == "danieladm"


def test_archivar_dos_veces_no_duplica(cfg, usuarios):
    db.archivar_cliente(cfg.seguridad.db_path, "x", "a")
    db.archivar_cliente(cfg.seguridad.db_path, "x", "b")

    assert len(db.listar_archivados(cfg.seguridad.db_path)) == 1


def test_desarchivar_dice_si_habia_algo(cfg, usuarios):
    db.archivar_cliente(cfg.seguridad.db_path, "x", "a")

    assert db.desarchivar_cliente(cfg.seguridad.db_path, "x") is True
    assert db.desarchivar_cliente(cfg.seguridad.db_path, "x") is False


# ------------------------------------------------------------ por la web

def test_no_se_puede_archivar_uno_valido(como_admin, csrf_admin, helper_falso, cfg):
    """
    La regla que sostiene todo lo demás.

    Ocultar de la lista un certificado que sigue sirviendo dejaría un acceso
    vivo fuera de la vista, que es lo contrario de lo que espera quien pulsa
    «eliminar».
    """
    respuesta = como_admin.post("/clientes/daniel/archivar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 400
    assert "Revócalo primero" in respuesta.text
    assert db.listar_archivados(cfg.seguridad.db_path) == []

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "archivar" and e["resultado"] == "error"
               for e in entradas)


def test_archivar_un_revocado(como_admin, csrf_admin, helper_falso, cfg):
    respuesta = como_admin.post("/clientes/antiguo-becario/archivar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    assert [a["cn"] for a in db.listar_archivados(cfg.seguridad.db_path)] \
        == ["antiguo-becario"]

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "archivar" and e["objetivo"] == "antiguo-becario"
               and e["resultado"] == "ok" for e in entradas)


def test_el_archivado_sale_de_la_lista_activa(como_admin, csrf_admin, helper_falso, cfg):
    como_admin.post("/clientes/antiguo-becario/archivar",
                    headers={"X-CSRF-Token": csrf_admin})

    tabla = como_admin.get("/clientes/tabla").text

    # Fuera de la tabla activa, pero presente en el histórico
    assert "Perfiles eliminados" in tabla
    assert "Devolver a la lista" in tabla
    # Los que siguen activos no se tocan
    assert "daniel" in tabla


def test_desarchivar_lo_devuelve(como_admin, csrf_admin, helper_falso, cfg):
    como_admin.post("/clientes/antiguo-becario/archivar",
                    headers={"X-CSRF-Token": csrf_admin})
    respuesta = como_admin.post("/clientes/antiguo-becario/desarchivar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    assert db.listar_archivados(cfg.seguridad.db_path) == []

    tabla = como_admin.get("/clientes/tabla").text
    assert "Perfiles eliminados" not in tabla


def test_desarchivar_algo_que_no_estaba(como_admin, csrf_admin, helper_falso):
    respuesta = como_admin.post("/clientes/daniel/desarchivar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 400
    assert "no estaba en los eliminados" in respuesta.text


def test_un_supervisor_no_puede_archivar(como_supervisor, csrf_supervisor,
                                         helper_falso, cfg):
    respuesta = como_supervisor.post("/clientes/antiguo-becario/archivar",
                                     headers={"X-CSRF-Token": csrf_supervisor})

    assert respuesta.status_code == 403
    assert db.listar_archivados(cfg.seguridad.db_path) == []


@pytest.mark.parametrize("cn", ["con espacio", "cliente;id", "server"])
def test_un_cn_invalido_no_llega_a_la_base(como_admin, csrf_admin, helper_falso,
                                           cfg, cn):
    respuesta = como_admin.post("/clientes/%s/archivar" % cn,
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 400
    assert db.listar_archivados(cfg.seguridad.db_path) == []
