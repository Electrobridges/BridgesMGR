"""
Verificación en dos pasos de la VPN.

El script que corre OpenVPN repite el algoritmo de app/core/totp.py: aquí se
comprueba que dan los mismos códigos, y que solo se le pide código a quien lo
tiene activado.
"""

import importlib.machinery
import importlib.util
import io
import json
import sys
import time
from pathlib import Path

import pytest

from app.core import easyrsa, eventos_vpn, serverconf, totp

RAIZ = Path(__file__).resolve().parents[1]


def _cargar(nombre, ruta):
    spec = importlib.util.spec_from_loader(
        nombre, importlib.machinery.SourceFileLoader(nombre, str(ruta)))
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="module")
def script():
    return _cargar("ovpn_web_verificar_totp", RAIZ / "deploy" / "ovpn-web-verificar-totp")


@pytest.fixture(scope="module")
def helper():
    return _cargar("ovpn_web_helper_totp", RAIZ / "deploy" / "ovpn-web-helper")


SECRETO = totp.generar_secreto()
AHORA = 1_760_000_000


def test_mismos_codigos_que_el_panel(script):
    for paso in range(AHORA // 30 - 3, AHORA // 30 + 3):
        assert script.codigo(SECRETO, paso) == totp.codigo(SECRETO, paso)


def test_mismas_constantes(script):
    assert (script.PERIODO, script.DIGITOS, script.VENTANA) == \
        (totp.PERIODO, totp.DIGITOS, totp.VENTANA)


def test_sin_secreto_entra_sin_codigo(script):
    """Con auth-user-pass-optional, a quien no lo tiene activado no se le pide nada."""
    assert script.decidir({"otra": SECRETO}, "ana", "", AHORA, None) == (None, None)


def test_con_secreto_exige_el_codigo(script):
    secretos = {"ana": SECRETO}
    bueno = totp.codigo(SECRETO, momento=AHORA)

    assert script.decidir(secretos, "ana", "", AHORA, None)[0] == "sin_codigo"
    assert script.decidir(secretos, "ana", "000000" if bueno != "000000" else "111111",
                          AHORA, None)[0] == "codigo_incorrecto"

    motivo, paso = script.decidir(secretos, "ana", bueno, AHORA, None)
    assert motivo is None and paso == AHORA // 30


def test_un_codigo_no_vale_dos_veces(script):
    bueno = totp.codigo(SECRETO, momento=AHORA)
    motivo, _ = script.decidir({"ana": SECRETO}, "ana", bueno, AHORA, AHORA // 30)
    assert motivo == "codigo_repetido"


def test_el_script_anota_el_paso_y_lo_respeta(script, tmp_path, monkeypatch, capsys):
    secretos = tmp_path / "totp-vpn.json"
    secretos.write_text(json.dumps({"ana": SECRETO}))
    estado = tmp_path / "estado"
    estado.mkdir()
    credenciales = tmp_path / "cred"
    credenciales.write_text("ana\n%s\n" % totp.codigo(SECRETO))

    monkeypatch.setattr(script, "SECRETOS", str(secretos))
    monkeypatch.setattr(script, "ESTADO", str(estado))
    monkeypatch.setenv("common_name", "ana")
    monkeypatch.setattr(sys, "argv", ["verificar-totp", str(credenciales)])

    with pytest.raises(SystemExit) as salida:
        script.main()
    assert salida.value.code == 0
    assert (estado / "ana").read_text() == str(int(time.time()) // 30)

    # El mismo código, otra vez: fuera
    with pytest.raises(SystemExit) as salida:
        script.main()
    assert salida.value.code == 1
    assert "motivo=codigo_repetido" in capsys.readouterr().out


def test_el_script_sin_archivo_deja_pasar(script, tmp_path, monkeypatch):
    monkeypatch.setattr(script, "SECRETOS", str(tmp_path / "no-existe.json"))
    monkeypatch.setenv("common_name", "ana")
    with pytest.raises(SystemExit) as salida:
        script.main()
    assert salida.value.code == 0


def test_el_script_con_secretos_ilegibles_rechaza(script, tmp_path, monkeypatch, capsys):
    secretos = tmp_path / "totp-vpn.json"
    secretos.write_text("{roto")
    monkeypatch.setattr(script, "SECRETOS", str(secretos))
    monkeypatch.setenv("common_name", "ana")
    with pytest.raises(SystemExit) as salida:
        script.main()
    assert salida.value.code == 1
    assert "secretos_ilegibles" in capsys.readouterr().out


def test_el_historial_reconoce_el_rechazo():
    e, = eventos_vpn.parse_eventos(["ovpn-web totp: RECHAZO cn=ana motivo=codigo_incorrecto"])
    assert e["tipo"] == eventos_vpn.RECHAZO_2FA and e["cn"] == "ana" and e["fallo"]
    assert e["detalle"] == "código de verificación incorrecto"


# ------------------------------------------------------------------ helper

PREPARADO = [
    ["script-security", "2"],
    ["group", "ovpnweb-vpn"],
    ["auth-user-pass-verify", "/usr/local/lib/ovpn-web/verificar-totp", "via-file"],
    ["auth-user-pass-optional"],
]


def test_requisitos_iguales_en_panel_y_helper(helper):
    for directivas in (PREPARADO, PREPARADO[:2], [], PREPARADO[1:]):
        assert helper.requisitos_dos_pasos(directivas) == serverconf.dos_pasos(directivas)


def test_el_helper_no_activa_con_el_servidor_sin_preparar(helper, monkeypatch, capsys):
    monkeypatch.setattr(helper, "leer_server_conf", lambda c: ("x", PREPARADO[:1]))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"accion": "alta", "cn": "ana", "secreto": SECRETO})))
    with pytest.raises(SystemExit):
        helper.cmd_totp_vpn({})
    assert "group ovpnweb-vpn" in capsys.readouterr().err


@pytest.mark.parametrize("doc", [
    {"accion": "alta", "cn": "ana", "secreto": "corto"},
    {"accion": "alta", "cn": "../ana", "secreto": SECRETO},
    {"accion": "borrar-todo"},
])
def test_el_helper_no_se_fia(helper, monkeypatch, doc):
    monkeypatch.setattr(helper, "leer_server_conf", lambda c: ("x", PREPARADO))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(doc)))
    with pytest.raises(SystemExit):
        helper.cmd_totp_vpn({})


def test_el_helper_guarda_sin_devolver_el_secreto(helper, monkeypatch, tmp_path):
    import grp
    import os
    monkeypatch.setattr(helper, "leer_server_conf", lambda c: ("x", PREPARADO))
    monkeypatch.setattr(helper, "DIR_POLITICAS", str(tmp_path))
    monkeypatch.setattr(helper, "ARCHIVO_TOTP", str(tmp_path / "totp-vpn.json"))
    monkeypatch.setattr(grp, "getgrnam", lambda n: type("G", (), {"gr_gid": os.getgid()}))
    monkeypatch.setattr(helper.os, "chown", lambda *a: None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"accion": "alta", "cn": "ana", "secreto": SECRETO})))

    resultado = helper.cmd_totp_vpn({})

    assert resultado["clientes"] == ["ana"]
    assert SECRETO not in json.dumps(resultado)
    assert json.loads((tmp_path / "totp-vpn.json").read_text()) == {"ana": SECRETO}
    assert oct((tmp_path / "totp-vpn.json").stat().st_mode & 0o777) == "0o640"


# ------------------------------------------------------------------- rutas

@pytest.fixture
def helper_falso(monkeypatch):
    estado = {"clientes": set(), "secretos": {}}

    def totp_vpn(cfg, accion, cn=None, secreto=None):
        if accion == "alta":
            estado["clientes"].add(cn)
            estado["secretos"][cn] = secreto
        elif accion == "baja":
            estado["clientes"].discard(cn)
        return sorted(estado["clientes"])

    monkeypatch.setattr(easyrsa, "totp_vpn", totp_vpn)
    monkeypatch.setattr(easyrsa, "server_conf",
                        lambda c: {"ruta": "x", "directivas": PREPARADO})
    return estado


def test_activar_ensena_la_clave_una_vez(como_admin, csrf_admin, helper_falso, cfg):
    from app import db
    r = como_admin.post("/clientes/ana/dos-pasos/activar", headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    secreto = helper_falso["secretos"]["ana"]
    assert totp.formatear_secreto(secreto) in r.text
    assert "Descárgale un" in r.text

    # Al volver a la página ya no se enseña
    r = como_admin.get("/clientes/ana/politica")
    assert totp.formatear_secreto(secreto) not in r.text
    assert "Se le pide el código al conectar" in r.text

    # Y en la base del panel no queda ni rastro del secreto
    with open(cfg.seguridad.db_path, "rb") as f:
        assert secreto.encode() not in f.read()
    assert db.listar_auditoria(cfg.seguridad.db_path, limite=1)[0]["accion"] == "dos_pasos_vpn"


def test_quitar(como_admin, csrf_admin, helper_falso):
    como_admin.post("/clientes/ana/dos-pasos/activar", headers={"X-CSRF-Token": csrf_admin})
    r = como_admin.post("/clientes/ana/dos-pasos/quitar", headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200
    assert helper_falso["clientes"] == set()


def test_la_pagina_dice_que_falta_en_el_servidor(como_admin, helper_falso, monkeypatch):
    monkeypatch.setattr(easyrsa, "server_conf", lambda c: {"ruta": "x", "directivas": []})
    r = como_admin.get("/clientes/ana/politica")
    assert "El servidor aún no puede pedir el código" in r.text
    assert "group ovpnweb-vpn" in r.text


def test_el_supervisor_no_activa(como_supervisor, csrf_supervisor, helper_falso):
    r = como_supervisor.post("/clientes/ana/dos-pasos/activar",
                             headers={"X-CSRF-Token": csrf_supervisor})
    assert r.status_code == 403
    assert helper_falso["clientes"] == set()
