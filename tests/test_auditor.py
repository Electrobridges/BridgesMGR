"""
Auditoría de endurecimiento del server.conf.
"""

import re
from pathlib import Path

import pytest

from app.core import auditor, easyrsa

RAIZ = Path(__file__).resolve().parents[1]


def _directivas(texto):
    return [l.split() for l in texto.splitlines() if l.strip() and not l.strip().startswith("#")]


def _conf_del_instalador():
    """
    El server.conf que escribe instalar-openvpn.sh, con sus variables puestas.

    Es la prueba de que lo que monta el propio proyecto pasa su auditoría: si
    alguien endurece el auditor, o afloja el instalador, esto lo dice.
    """
    texto = (RAIZ / "deploy" / "instalar-openvpn.sh").read_text(encoding="utf-8")
    bloque = texto.split("cat <<FIN\n# Generado por deploy/instalar-openvpn.sh", 1)[1].split("\nFIN\n", 1)[0]
    valores = {
        "PUERTO": "1194", "PROTO": "udp", "EASYRSA_DIR": "/etc/openvpn/easy-rsa",
        "TLS_CRYPT": "/etc/openvpn/tls-crypt.key", "RED_VPN_DIR": "10.8.0.0",
        "RED_VPN_MASK": "255.255.255.0", "POOL_INI": "10.8.0.2", "POOL_FIN": "10.8.0.191",
        "LOG_DIR": "/var/log/openvpn", "HOOK_CLIENT_CONNECT": "/usr/local/lib/ovpn-web/client-connect",
        "MGMT_HOST": "127.0.0.1", "MGMT_PORT": "7505", "STATUS_FILE": "/var/log/openvpn/status.log",
        "LOG_FILE": "/var/log/openvpn/openvpn.log",
    }
    bloque = re.sub(r"\$\{(\w+)\}", lambda m: valores[m.group(1)], bloque)
    return _directivas(bloque)


def _claves(informe, nivel):
    return {h["clave"] for h in informe["hallazgos"] if h["nivel"] == nivel}


def test_lo_que_monta_el_instalador_pasa_la_auditoria():
    informe = auditor.auditar(_conf_del_instalador(), "OpenVPN 2.6.14 x86_64-pc-linux-gnu")
    assert _claves(informe, auditor.CRITICO) == set()
    assert _claves(informe, auditor.AVISO) == set()
    assert informe["nota"] >= 90


DEBIL = """
port 1194
dev tun
server 10.8.0.0 255.255.255.0
cipher BF-CBC
auth SHA1
tls-version-min 1.0
comp-lzo
duplicate-cn
client-to-client
management 0.0.0.0 7505
verb 1
reneg-sec 0
"""


def test_un_servidor_flojo_suspende():
    informe = auditor.auditar(_directivas(DEBIL), "OpenVPN 2.6.3 x86_64")
    criticos = _claves(informe, auditor.CRITICO)
    assert {"tls", "cifrado", "crl", "compresion", "management", "cve"} <= criticos
    avisos = _claves(informe, auditor.AVISO)
    assert {"tls-min", "auth", "duplicate-cn", "client-to-client", "privilegios", "verb",
            "reneg", "politicas", "remote-cert"} <= avisos
    assert informe["nota"] == 0
    # Ordenados de más grave a menos
    niveles = [h["nivel"] for h in informe["hallazgos"]]
    assert niveles == sorted(niveles, key=auditor.NIVELES.index)


def test_cada_fallo_trae_su_arreglo():
    informe = auditor.auditar(_directivas(DEBIL), "OpenVPN 2.6.3")
    for h in informe["hallazgos"]:
        if h["nivel"] in (auditor.CRITICO, auditor.AVISO):
            assert h["arreglo"], "'%s' no dice cómo se arregla" % h["titulo"]


@pytest.mark.parametrize("version, extra, cve", [
    ("OpenVPN 2.6.5 x", [], "CVE-2023-46850"),
    ("OpenVPN 2.6.13 x", [["tls-crypt-v2", "/etc/openvpn/v2.key"]], "CVE-2025-2704"),
    ("OpenVPN 2.6.13 x", [], None),
    ("OpenVPN 2.6.14 x", [["tls-crypt-v2", "/etc/openvpn/v2.key"]], None),
])
def test_cves_por_version(version, extra, cve):
    informe = auditor.auditar(_conf_del_instalador() + extra, version)
    encontrados = [h["titulo"] for h in informe["hallazgos"] if h["clave"] == "cve"]
    if cve:
        assert any(cve in t for t in encontrados)
    else:
        assert encontrados == []


def test_la_crl_caducada_es_critica():
    informe = auditor.auditar(_conf_del_instalador(), "OpenVPN 2.6.14", crl_dias=-1)
    assert "crl-fecha" in _claves(informe, auditor.CRITICO)


def test_version_openvpn():
    assert auditor.version_openvpn("OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL]") == (2, 5, 1)
    assert auditor.version_openvpn("") is None


def test_la_pagina_es_solo_de_quien_manda(como_supervisor):
    assert como_supervisor.get("/seguridad").status_code == 403


def test_la_pagina_muestra_el_informe(como_admin, monkeypatch):
    monkeypatch.setattr(easyrsa, "server_conf", lambda c: {
        "ruta": "/etc/openvpn/server/server.conf",
        "directivas": _directivas(DEBIL), "version": "OpenVPN 2.6.3 x86_64"})
    r = como_admin.get("/seguridad")
    assert r.status_code == 200
    assert "Sin tls-crypt ni tls-auth" in r.text
    assert "allow-compression no" in r.text


def test_la_pagina_dice_por_que_no_puede_auditar(como_admin):
    # Sin helper en las pruebas: tiene que decirlo, no enseñar una nota vacía
    r = como_admin.get("/seguridad")
    assert r.status_code == 200
    assert "No se pudo leer el server.conf" in r.text
