"""
Operación: caducidad de certificados, tráfico por cliente, cuotas y métricas.
"""

import importlib.machinery
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import caducidades, db, notificar, trafico
from app.core import easyrsa
from app.core import politicas as pol

RAIZ = Path(__file__).resolve().parents[1]


@pytest.fixture
def base(cfg):
    db.init_db(cfg.seguridad.db_path)
    return cfg


@pytest.fixture
def avisos(monkeypatch):
    lista = []
    monkeypatch.setattr(notificar, "avisar",
                        lambda c, cat, asunto, cuerpo, grave=False: lista.append((asunto, grave)))
    return lista


# ----------------------------------------------------------- caducidades

@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_loader(
        "ovpn_web_helper_op",
        importlib.machinery.SourceFileLoader("ovpn_web_helper_op",
                                             str(RAIZ / "deploy" / "ovpn-web-helper")))
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_el_helper_lee_las_fechas_del_indice(helper, tmp_path, monkeypatch):
    pki = tmp_path / "easy-rsa" / "pki"
    pki.mkdir(parents=True)
    (pki / "index.txt").write_text(
        "V\t270125234826Z\t\t01\tunknown\t/CN=ana\n"
        "R\t270125234826Z\t250101000000Z\t02\tunknown\t/CN=viejo\n"
        "V\t351231000000Z\t\t03\tunknown\t/CN=server_X\n"
    )
    monkeypatch.setattr(helper, "cn_del_servidor", lambda c: "server_X")

    datos = helper.cmd_caducidades({"openvpn": {"easyrsa_path": str(tmp_path / "easy-rsa")}})

    # Ni el revocado ni el del propio servidor cuentan como cliente
    assert datos["clientes"] == {"ana": "2027-01-25T23:48:26Z"}


def _cache(cfg, datos):
    db.guardar_ajuste(cfg.seguridad.db_path, caducidades.AJUSTE_CACHE,
                      json.dumps({"leido": datetime.now(timezone.utc).isoformat(), "datos": datos}))


def _dentro(dias):
    return (datetime.now(timezone.utc) + timedelta(days=dias, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_avisa_por_escalones_y_una_vez(base, avisos):
    _cache(base, {"clientes": {"ana": _dentro(20), "luis": _dentro(400)},
                  "ca": _dentro(5), "servidor": None})

    caducidades.revisar(base)
    caducidades.revisar(base)

    asuntos = [a for a, _ in avisos]
    assert len(asuntos) == 2
    assert any("La CA caduca en 5" in a for a in asuntos)
    assert any("'ana' caduca en 20" in a for a in asuntos)
    # La CA deja fuera a todos: siempre grave
    assert dict(avisos)[next(a for a in asuntos if "La CA" in a)] is True


def test_la_tabla_marca_el_certificado_que_caduca_pronto(base, como_admin, monkeypatch):
    monkeypatch.setattr(easyrsa, "listar_certificados",
                        lambda c: {"validos": ["ana", "luis"], "revocados": []})
    _cache(base, {"clientes": {"ana": _dentro(10), "luis": _dentro(400)}, "ca": None,
                  "servidor": None})
    r = como_admin.get("/clientes/tabla")
    assert "certificado caduca en 10 d" in r.text
    assert r.text.count("certificado caduca") == 1


def test_emitir_invalida_la_cache(base, como_admin, csrf_admin, monkeypatch):
    monkeypatch.setattr(easyrsa, "crear_cliente", lambda c, cn, clave=None: {"ok": True})
    _cache(base, {"clientes": {}, "ca": None, "servidor": None})
    como_admin.post("/clientes", data={"cn": "nuevo"}, headers={"X-CSRF-Token": csrf_admin})
    assert caducidades.cache(base.seguridad.db_path) is None


# --------------------------------------------------------------- tráfico

def _con(cn, recv, sent, desde=1000):
    return {"user": cn, "real_ip": "203.0.113.5:4444", "bytes_recv": recv,
            "bytes_sent": sent, "connected_since_epoch": desde}


def test_suma_solo_lo_que_crece(base):
    dia = datetime(2026, 10, 14, 12, 0)
    assert trafico.muestrear(base, [_con("ana", 100, 1000)], dia) == {"ana": (100, 1000)}
    assert trafico.muestrear(base, [_con("ana", 150, 1500)], dia) == {"ana": (50, 500)}
    # Reconexión: sesión nueva, cuenta entera
    assert trafico.muestrear(base, [_con("ana", 30, 40, desde=2000)], dia) == {"ana": (30, 40)}

    assert db.trafico_mes(base.seguridad.db_path, "2026-10") == {"ana": (180, 1540)}


def test_sobrevive_a_un_reinicio(base):
    """La última vista va a la base: lo de mientras el panel estaba parado cuenta."""
    dia = datetime(2026, 10, 14, 12, 0)
    trafico.muestrear(base, [_con("ana", 100, 100)], dia)
    trafico.muestrear(base, [_con("ana", 900, 900)], dia)
    assert db.trafico_mes(base.seguridad.db_path, "2026-10")["ana"] == (900, 900)


def test_bytes_decimales():
    assert trafico.bytes_decimales(999) == "999 B"
    assert trafico.bytes_decimales(5_000_000_000) == "5.0 GB"


# ---------------------------------------------------------------- cuotas

@pytest.fixture
def helper_politicas(monkeypatch):
    documentos = []
    monkeypatch.setattr(easyrsa, "aplicar_politicas",
                        lambda c, d: documentos.append(d) or {"ok": True})
    return documentos


def test_bloquea_al_agotar_la_cuota_y_libera_al_mes_siguiente(base, helper_politicas, avisos):
    ruta = base.seguridad.db_path
    db.guardar_politica(ruta, "ana", pol.normalizar({"cuota_mb_mes": 1}), "jefa")
    octubre = datetime(2026, 10, 14, 12, 0)

    trafico.muestrear(base, [_con("ana", 600_000, 500_000)], octubre)
    assert trafico.revisar_cuotas(base, octubre) == ["ana"]
    assert db.obtener_politica(ruta, "ana")["bloqueo"] == pol.BLOQUEO_CUOTA
    assert helper_politicas[-1]["clientes"]["ana"]["bloqueo"] == "cuota"

    # Mientras siga agotada no se repite
    assert trafico.revisar_cuotas(base, octubre) == []

    noviembre = datetime(2026, 11, 1, 0, 1)
    assert trafico.revisar_cuotas(base, noviembre) == ["ana"]
    assert db.obtener_politica(ruta, "ana")["bloqueo"] == ""

    acciones = [e["accion"] for e in db.listar_auditoria(ruta)]
    assert acciones[:2] == ["cuota_restablecida", "cuota_agotada"]


def test_la_cuota_se_guarda_desde_el_formulario(como_admin, csrf_admin, helper_politicas, cfg,
                                                monkeypatch):
    monkeypatch.setattr(easyrsa, "server_conf", lambda c: {"ruta": "x", "directivas": []})
    r = como_admin.post("/clientes/ana/politica", data={"cuota_gb": "2,5"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    assert db.obtener_politica(cfg.seguridad.db_path, "ana")["cuota_mb_mes"] == 2500


def test_la_cuota_no_la_borra_quien_edita_otra_cosa(como_admin, csrf_admin, helper_politicas,
                                                    cfg):
    """El bloqueo por cuota lo pone el panel; guardar el formulario no lo levanta."""
    db.guardar_politica(cfg.seguridad.db_path, "ana",
                        pol.normalizar({"cuota_mb_mes": 1, "bloqueo": "cuota"}), "jefa")
    como_admin.post("/clientes/ana/politica", data={"cuota_gb": "0.001", "max_sesion_min": "60"},
                    headers={"X-CSRF-Token": csrf_admin})
    assert db.obtener_politica(cfg.seguridad.db_path, "ana")["bloqueo"] == "cuota"


# -------------------------------------------------------------- métricas

def test_metricas_apagadas_por_defecto(cliente):
    assert cliente.get("/metrics").status_code == 404


@pytest.fixture
def con_token(cfg):
    cfg.seguridad.metricas_token = "secreto-de-prueba"
    return cfg


def test_metricas_exigen_el_token(con_token):
    from fastapi.testclient import TestClient

    from app.main import crear_app
    with TestClient(crear_app(con_token)) as c:
        assert c.get("/metrics").status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer otro"}).status_code == 401

        db.sumar_trafico(con_token.seguridad.db_path, trafico.mes_actual() + "-01",
                         {"ana": (10, 20)})
        r = c.get("/metrics", headers={"Authorization": "Bearer secreto-de-prueba"})

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert 'ovpnweb_trafico_mes_bytes{cn="ana",sentido="recibido"} 10' in r.text
    assert "ovpnweb_clientes_conectados 0" in r.text
    assert "# TYPE ovpnweb_rechazos_24h gauge" in r.text


def test_las_etiquetas_se_escapan():
    from app.routers.metricas import _etiqueta
    assert _etiqueta('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
