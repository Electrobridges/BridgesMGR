"""
Bloqueo automático de IPs.
"""

import importlib.machinery
import importlib.util
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import bloqueos, db, notificar, vigilante
from app.core import easyrsa, eventos_vpn

RAIZ = Path(__file__).resolve().parents[1]


@pytest.fixture
def cortafuegos(monkeypatch):
    estado = {"bloquear": [], "desbloquear": [], "falla": None}

    def doble(cfg, bloquear=(), desbloquear=()):
        if estado["falla"]:
            raise easyrsa.ErrorHelper(estado["falla"])
        estado["bloquear"] += list(bloquear)
        estado["desbloquear"] += list(desbloquear)
        return []

    monkeypatch.setattr(easyrsa, "bloqueos", doble)
    monkeypatch.setattr(easyrsa, "listar_bloqueos", lambda c: {"nft": True, "bloqueadas": []})
    return estado


def _rechazos(cfg, ip, n, tipo=eventos_vpn.RECHAZO_CLAVE):
    db.guardar_eventos_vpn(cfg.seguridad.db_path, [
        {"ts": "", "tipo": tipo, "cn": "", "ip": ip, "puerto": "1", "detalle": None}
    ] * n)


def _activar(cfg, **cambios):
    datos = dict(activo=True, umbral="5", ventana_min="10", duracion_min="60",
                 blanca="192.168.0.0/16")
    datos.update(cambios)
    bloqueos.guardar_ajustes(cfg.seguridad.db_path, datos["activo"], datos["umbral"],
                             datos["ventana_min"], datos["duracion_min"], datos["blanca"])


@pytest.fixture
def base(cfg):
    db.init_db(cfg.seguridad.db_path)
    return cfg


def test_reconoce_los_paquetes_sin_clave():
    linea = ("2026-07-30 10:00:01 TLS Error: tls-crypt unwrapping failed from "
             "[AF_INET]203.0.113.5:4444")
    e, = eventos_vpn.parse_eventos([linea])
    assert e["tipo"] == eventos_vpn.RECHAZO_CLAVE
    assert (e["ip"], e["puerto"]) == ("203.0.113.5", "4444")


def test_apagado_no_bloquea(base, cortafuegos):
    _rechazos(base, "203.0.113.5", 50)
    assert bloqueos.revisar(base) == []
    assert cortafuegos["bloquear"] == []


def test_bloquea_al_superar_el_umbral(base, cortafuegos, monkeypatch):
    avisos = []
    monkeypatch.setattr(notificar, "avisar", lambda c, cat, *a, **k: avisos.append(cat))
    _activar(base)
    _rechazos(base, "203.0.113.5", 5)
    _rechazos(base, "198.51.100.7", 4)

    assert bloqueos.revisar(base) == ["203.0.113.5"]
    assert cortafuegos["bloquear"] == [("203.0.113.5", 60)]
    assert [b["ip"] for b in db.bloqueos_activos(base.seguridad.db_path)] == ["203.0.113.5"]
    assert avisos == [notificar.RECHAZOS]

    # La siguiente vuelta no la vuelve a bloquear
    assert bloqueos.revisar(base) == []


def test_la_lista_blanca_no_se_bloquea(base, cortafuegos):
    _activar(base)
    _rechazos(base, "192.168.1.50", 50)
    assert bloqueos.revisar(base) == []


@pytest.mark.parametrize("tipo", [eventos_vpn.RECHAZO_REVOCADO, eventos_vpn.RECHAZO_POLITICA])
def test_los_clientes_cortados_no_cuentan(base, cortafuegos, tipo):
    """
    Un revocado o uno fuera de horario reintenta solo cada pocos segundos. Si
    comparte la IP de una oficina, bloquearla dejaría fuera a toda la oficina.
    """
    _activar(base)
    _rechazos(base, "203.0.113.5", 50, tipo)
    assert bloqueos.revisar(base) == []


def test_fuera_de_la_ventana_no_cuenta(base, cortafuegos):
    from datetime import timedelta
    _activar(base)
    _rechazos(base, "203.0.113.5", 50)
    luego = datetime.now(timezone.utc) + timedelta(minutes=11)
    assert bloqueos.revisar(base, ahora=luego) == []


def test_el_vigilante_revisa_tras_ingerir(base, cortafuegos, monkeypatch):
    _activar(base)
    with open(base.openvpn.log_path, "w", encoding="utf-8") as f:
        for _ in range(6):
            f.write("2026-07-30 10:00:01 TLS Error: tls-crypt unwrapping failed from "
                    "[AF_INET]203.0.113.5:4444\n")
    vigilante._ingerir_eventos(base)
    assert cortafuegos["bloquear"] == [("203.0.113.5", 60)]


@pytest.mark.parametrize("cambio, mensaje", [
    ({"umbral": "1"}, "umbral"),
    ({"ventana_min": "x"}, "número"),
    ({"blanca": "no-es-una-red"}, "lista blanca"),
])
def test_ajustes_invalidos(base, cambio, mensaje):
    with pytest.raises(bloqueos.AjusteInvalido, match=mensaje):
        _activar(base, **cambio)


# ------------------------------------------------------------------ rutas

def test_bloquear_y_desbloquear_a_mano(como_admin, csrf_admin, cortafuegos, cfg):
    r = como_admin.post("/seguridad/bloqueos", data={"ip": "203.0.113.9", "minutos": "30"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    assert cortafuegos["bloquear"] == [("203.0.113.9", 30)]

    r = como_admin.get("/seguridad/bloqueos/tabla")
    assert "203.0.113.9" in r.text

    r = como_admin.post("/seguridad/bloqueos/203.0.113.9/levantar",
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200
    assert cortafuegos["desbloquear"] == ["203.0.113.9"]
    assert db.bloqueos_activos(cfg.seguridad.db_path) == []


def test_no_te_puedes_bloquear_a_ti_mismo(como_admin, csrf_admin, cortafuegos, monkeypatch):
    import app.routers.seguridad as mod
    monkeypatch.setattr(mod, "ip_cliente", lambda request: "203.0.113.9")

    r = como_admin.post("/seguridad/bloqueos", data={"ip": "203.0.113.9", "minutos": "30"},
                        headers={"X-CSRF-Token": csrf_admin})

    assert r.status_code == 400
    assert "tu propia IP" in r.text
    assert cortafuegos["bloquear"] == []


def test_ajustes_desde_la_pagina(como_admin, csrf_admin, cfg):
    r = como_admin.post("/seguridad/bloqueos/ajustes", data={
        "activo": "1", "umbral": "8", "ventana_min": "15", "duracion_min": "120",
        "lista_blanca": "10.0.0.0/8\n"}, headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    a = bloqueos.ajustes(cfg.seguridad.db_path)
    assert a == {"activo": True, "umbral": 8, "ventana_min": 15, "duracion_min": 120,
                 "lista_blanca": ["10.0.0.0/8"]}


def test_el_supervisor_no_bloquea(como_supervisor, csrf_supervisor, cortafuegos):
    r = como_supervisor.post("/seguridad/bloqueos", data={"ip": "203.0.113.9"},
                             headers={"X-CSRF-Token": csrf_supervisor})
    assert r.status_code == 403


# ------------------------------------------------------------------ helper

@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_loader(
        "ovpn_web_helper_bloq",
        importlib.machinery.SourceFileLoader("ovpn_web_helper_bloq",
                                             str(RAIZ / "deploy" / "ovpn-web-helper")))
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1",
                                "1.2.3.4; flush ruleset", "::1", "nada"])
def test_el_helper_no_bloquea_lo_imbloqueable(helper, ip):
    assert helper._ip_bloqueable(ip) is None


def test_el_helper_escribe_la_orden_desde_la_ip_validada(helper, monkeypatch):
    ordenes = []
    monkeypatch.setattr(helper, "_asegurar_tabla_bloqueo", lambda: None)
    monkeypatch.setattr(helper, "_listar_bloqueadas", lambda: [])
    monkeypatch.setattr(helper, "_nft_ejecutar", lambda args, entrada=None: ordenes.append(entrada))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"bloquear": [{"ip": "203.0.113.5", "minutos": 60}]})))

    helper.cmd_bloqueos({})

    assert ordenes == ["add element inet ovpnweb_bloqueo bloqueadas { 203.0.113.5 timeout 60m }\n"]


@pytest.mark.parametrize("doc", [
    {"bloquear": [{"ip": "203.0.113.5", "minutos": 0}]},
    {"bloquear": [{"ip": "203.0.113.5", "minutos": True}]},
    {"bloquear": [{"ip": "203.0.113.5"}]},
    {"bloquear": [{"ip": "127.0.0.1", "minutos": 5}]},
    {"vaciar": True},
])
def test_el_helper_rechaza_documentos_raros(helper, monkeypatch, doc):
    monkeypatch.setattr(helper, "_asegurar_tabla_bloqueo", lambda: None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(doc)))
    with pytest.raises(SystemExit):
        helper.cmd_bloqueos({})
