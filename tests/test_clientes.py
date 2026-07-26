"""
Rutas de gestión de clientes VPN.

El helper privilegiado no existe en el entorno de pruebas, así que se sustituye
por dobles. Lo que se comprueba aquí es el comportamiento del panel: validación,
auditoría y traducción de errores.
"""

import pytest

from app import db
from app.core import easyrsa


@pytest.fixture
def helper_falso(monkeypatch):
    """Sustituye las llamadas al helper por respuestas controladas"""
    estado = {
        "validos": ["daniel", "portatil.oficina"],
        "revocados": ["antiguo-becario"],
        "llamadas": [],
    }

    def listar(cfg):
        return {"validos": estado["validos"], "revocados": estado["revocados"]}

    def revocar(cfg, cn):
        estado["llamadas"].append(("revocar", cn))
        estado["validos"].remove(cn)
        estado["revocados"].append(cn)
        return {"ok": True}

    def crear(cfg, cn):
        estado["llamadas"].append(("crear", cn))
        estado["validos"].append(cn)
        return {"ok": True}

    def restaurar(cfg, cn):
        estado["llamadas"].append(("restaurar", cn))
        estado["revocados"].remove(cn)
        estado["validos"].append(cn)
        return {"ok": True}

    def ovpn(cfg, cn):
        estado["llamadas"].append(("ovpn", cn))
        return "client\nremote vpn.ejemplo.com 1194\n"

    for nombre, doble in [
        ("listar_certificados", listar), ("revocar", revocar), ("crear_cliente", crear),
        ("restaurar", restaurar), ("generar_ovpn", ovpn),
    ]:
        monkeypatch.setattr(easyrsa, nombre, doble)
        # Los routers importan el módulo, no las funciones sueltas, pero
        # panel.py sí importa dos por nombre: hay que parchear allí también
        for modulo in ("app.routers.clientes", "app.routers.panel"):
            import importlib
            mod = importlib.import_module(modulo)
            if hasattr(mod, nombre):
                monkeypatch.setattr(mod, nombre, doble)

    return estado


def test_tabla_lista_validos_y_revocados(como_admin, helper_falso):
    respuesta = como_admin.get("/clientes/tabla")

    assert respuesta.status_code == 200
    assert "daniel" in respuesta.text
    assert "antiguo-becario" in respuesta.text
    assert "revocado" in respuesta.text


def test_crear_cliente(como_admin, csrf_admin, helper_falso):
    respuesta = como_admin.post(
        "/clientes", data={"cn": "nuevo-portatil"}, headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 200
    assert ("crear", "nuevo-portatil") in helper_falso["llamadas"]


@pytest.mark.parametrize("cn", ["con espacio", "../../etc/passwd", "cliente;id", "server"])
def test_cn_invalido_no_llega_al_helper(como_admin, csrf_admin, helper_falso, cn):
    """La validación debe cortar ANTES de invocar nada privilegiado"""
    respuesta = como_admin.post(
        "/clientes", data={"cn": cn}, headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert helper_falso["llamadas"] == []


def test_revocar_audita(como_admin, csrf_admin, helper_falso, cfg):
    respuesta = como_admin.post(
        "/clientes/daniel/revocar", headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 200
    assert ("revocar", "daniel") in helper_falso["llamadas"]

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "revocar" and e["objetivo"] == "daniel"
               and e["resultado"] == "ok" for e in entradas)


def test_error_del_helper_se_muestra_y_audita(como_admin, csrf_admin, helper_falso,
                                              monkeypatch, cfg):
    def revocar_falla(cfg_, cn):
        raise easyrsa.ErrorHelper("easyrsa revoke falló: no such file")

    import app.routers.clientes as rc
    monkeypatch.setattr(rc.easyrsa, "revocar", revocar_falla)

    respuesta = como_admin.post(
        "/clientes/daniel/revocar", headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert "no such file" in respuesta.text

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "revocar" and e["resultado"] == "error" for e in entradas)


def test_descargar_ovpn(como_admin, helper_falso):
    respuesta = como_admin.get("/clientes/daniel/ovpn")

    assert respuesta.status_code == 200
    assert respuesta.headers["content-disposition"] == 'attachment; filename="daniel.ovpn"'
    assert "remote vpn.ejemplo.com 1194" in respuesta.text


def test_descarga_queda_auditada(como_admin, helper_falso, cfg):
    como_admin.get("/clientes/daniel/ovpn")

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "descargar_ovpn" and e["objetivo"] == "daniel"
               for e in entradas)


def test_conexiones_informan_el_fallo_del_management(como_admin):
    """
    El puerto de management está cerrado y no hay archivo de status: la tabla
    debe explicar por qué, no fingir que no hay nadie conectado.
    """
    respuesta = como_admin.get("/conexiones/tabla")

    assert respuesta.status_code == 200
    assert "Management interface" in respuesta.text
    assert "no disponible" in respuesta.text
