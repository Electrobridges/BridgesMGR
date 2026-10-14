"""
Políticas por cliente: validación, evaluación y las dos copias del otro lado
de la frontera (el helper y el script client-connect).

La evaluación vive en tres sitios a propósito —el panel decide a quién
expulsar, el script a quién dejar entrar y el helper qué escribir—, así que
aquí se comprueba que las tres dicen lo mismo con los mismos casos.
"""

import importlib.machinery
import importlib.util
import io
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

from app.core import politicas as pol

RAIZ = Path(__file__).resolve().parents[1]


def _cargar(nombre, ruta):
    spec = importlib.util.spec_from_loader(
        nombre, importlib.machinery.SourceFileLoader(nombre, str(ruta)))
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="module")
def helper():
    return _cargar("ovpn_web_helper_pol", RAIZ / "deploy" / "ovpn-web-helper")


@pytest.fixture(scope="module")
def gancho():
    return _cargar("ovpn_web_client_connect", RAIZ / "deploy" / "ovpn-web-client-connect")


LABORABLES = [{"dias": [0, 1, 2, 3, 4], "desde": "08:00", "hasta": "19:00"}]

# Lunes 13 de octubre de 2025, en distintas horas
LUNES_10 = datetime(2025, 10, 13, 10, 0)
LUNES_19 = datetime(2025, 10, 13, 19, 0)
LUNES_0759 = datetime(2025, 10, 13, 7, 59)
SABADO_10 = datetime(2025, 10, 18, 10, 0)


# --------------------------------------------------------------- validación

def test_la_vacia_es_canonica():
    assert pol.normalizar({}) == pol.vacia()
    assert pol.es_vacia({"destinos": [], "horario": []})


def test_los_destinos_se_escriben_en_forma_canonica():
    p = pol.normalizar({
        "ip_fija": "10.8.0.200",
        "destinos": ["192.168.1.7", "192.168.1.9/24", "192.168.1.10:443/tcp", "192.168.1.7/32"],
    })
    # El duplicado se cae; la red mal alineada se alinea
    assert p["destinos"] == ["192.168.1.7/32", "192.168.1.0/24", "192.168.1.10/32:443/tcp"]


@pytest.mark.parametrize("destino", [
    "192.168.1.300", "cualquiera", "10.0.0.0/33", "10.0.0.1:0/tcp", "10.0.0.1:70000/tcp",
    "10.0.0.1:80/icmp", "10.0.0.1:80", "10.0.0.1; drop",
])
def test_destinos_raros_se_rechazan(destino):
    with pytest.raises(pol.PoliticaInvalida):
        pol.normalizar({"ip_fija": "10.8.0.200", "destinos": [destino]})


def test_limitar_destinos_exige_ip_fija():
    """
    La regla de nftables va contra la IP de origen. Sin IP fija no hay contra
    qué escribirla, y aceptar la política prometería un límite inexistente.
    """
    with pytest.raises(pol.PoliticaInvalida, match="IP fija"):
        pol.normalizar({"destinos": ["192.168.1.0/24"]})


@pytest.mark.parametrize("franja", [
    {"dias": [], "desde": "08:00", "hasta": "19:00"},
    {"dias": [7], "desde": "08:00", "hasta": "19:00"},
    {"dias": [True], "desde": "08:00", "hasta": "19:00"},
    {"dias": [0], "desde": "8:00", "hasta": "19:00"},
    {"dias": [0], "desde": "19:00", "hasta": "08:00"},
    {"dias": [0], "desde": "24:00", "hasta": "24:00"},
    {"dias": [0], "desde": "10:00", "hasta": "10:00"},
])
def test_franjas_mal_formadas(franja):
    with pytest.raises(pol.PoliticaInvalida):
        pol.normalizar({"horario": [franja]})


def test_la_franja_puede_acabar_a_medianoche():
    p = pol.normalizar({"horario": [{"dias": [4, 4, 0], "desde": "22:00", "hasta": "24:00"}]})
    assert p["horario"] == [{"dias": [0, 4], "desde": "22:00", "hasta": "24:00"}]


def test_campos_desconocidos_se_rechazan():
    with pytest.raises(pol.PoliticaInvalida, match="desconocidos"):
        pol.normalizar({"ip": "10.8.0.200"})


def test_documento_rechaza_ips_repetidas():
    with pytest.raises(pol.PoliticaInvalida, match="más de un cliente"):
        pol.documento({
            "ana": {"ip_fija": "10.8.0.200"},
            "luis": {"ip_fija": "10.8.0.200"},
        })


def test_documento_omite_las_vacias():
    doc = pol.documento({"ana": {}, "luis": {"max_sesion_min": 60}}, 0)
    assert list(doc["clientes"]) == ["luis"]
    assert doc["version"] == pol.VERSION


# --------------------------------------------------------------- evaluación

@pytest.mark.parametrize("ahora, esperado", [
    (LUNES_10, None),
    (LUNES_0759, pol.MOTIVO_HORARIO),
    # El final de la franja ya está fuera: 'de 8 a 19' es hasta las 19:00
    (LUNES_19, pol.MOTIVO_HORARIO),
    (SABADO_10, pol.MOTIVO_HORARIO),
])
def test_horario(ahora, esperado):
    assert pol.motivo_rechazo({"horario": LABORABLES}, ahora) == esperado


def test_caducidad():
    p = {"expira": "2025-10-13T10:00"}
    assert pol.motivo_rechazo(p, datetime(2025, 10, 13, 9, 59)) is None
    assert pol.motivo_rechazo(p, LUNES_10) == pol.MOTIVO_CADUCADO


def test_el_bloqueo_manda_sobre_todo():
    p = {"bloqueo": pol.BLOQUEO_CUOTA, "horario": LABORABLES}
    assert pol.motivo_rechazo(p, LUNES_10) == pol.MOTIVO_BLOQUEO


def test_duracion_maxima_propia_y_global():
    assert pol.motivo_expulsion({}, 60, 3599, LUNES_10) is None
    assert pol.motivo_expulsion({}, 60, 3600, LUNES_10) == pol.MOTIVO_DURACION
    # La propia gana a la global, en los dos sentidos
    assert pol.motivo_expulsion({"max_sesion_min": 120}, 60, 3600, LUNES_10) is None
    assert pol.motivo_expulsion({"max_sesion_min": 30}, 0, 1800, LUNES_10) == pol.MOTIVO_DURACION
    # Sin duración conocida no se expulsa por duración
    assert pol.motivo_expulsion({}, 60, None, LUNES_10) is None


def test_describir_horario():
    assert pol.describir_horario(LABORABLES) == "L–V 08:00–19:00"
    assert pol.describir_horario([{"dias": [5, 6], "desde": "09:00", "hasta": "13:00"}]) \
        == "S,D 09:00–13:00"


# ------------------------------------------------ las copias del otro lado

CASOS = [
    ({}, LUNES_10),
    ({"horario": LABORABLES}, LUNES_10),
    ({"horario": LABORABLES}, LUNES_19),
    ({"horario": LABORABLES}, SABADO_10),
    ({"expira": "2025-10-13T10:00"}, LUNES_10),
    ({"expira": "2025-10-13T10:01"}, LUNES_10),
    ({"bloqueo": "cuota"}, LUNES_10),
]


@pytest.mark.parametrize("politica, ahora", CASOS)
def test_el_script_de_conexion_decide_lo_mismo_que_el_panel(gancho, politica, ahora):
    p = pol.normalizar(politica)
    assert gancho.motivo_rechazo(p, ahora) == pol.motivo_rechazo(p, ahora)


def test_constantes_identicas_en_el_helper(helper):
    assert helper.VERSION_POLITICAS == pol.VERSION
    assert helper.MAX_DESTINOS == pol.MAX_DESTINOS
    assert helper.MAX_FRANJAS == pol.MAX_FRANJAS
    assert helper.MAX_SESION_MIN == pol.MAX_SESION_MIN
    assert helper.BLOQUEOS == set(pol.BLOQUEOS)
    assert helper.CAMPOS_POLITICA == set(pol.vacia())


def test_el_script_fija_la_ip(gancho):
    doc = {"mascara": "255.255.255.0",
           "clientes": {"ana": pol.normalizar({"ip_fija": "10.8.0.200"})}}
    assert gancho.decidir(doc, "ana", LUNES_10) == (None, ["ifconfig-push 10.8.0.200 255.255.255.0"])
    # Quien no tiene política entra sin más
    assert gancho.decidir(doc, "luis", LUNES_10) == (None, [])


def test_el_script_rechaza_y_lo_dice_en_el_log(gancho, tmp_path, monkeypatch, capsys):
    archivo = tmp_path / "politicas.json"
    archivo.write_text(json.dumps({"clientes": {"ana": pol.normalizar({"bloqueo": "cuota"})}}))
    monkeypatch.setattr(gancho, "ARCHIVO", str(archivo))
    monkeypatch.setenv("common_name", "ana")
    monkeypatch.setattr(sys, "argv", ["client-connect", str(tmp_path / "dinamico")])

    with pytest.raises(SystemExit) as salida:
        gancho.main()

    assert salida.value.code == 1
    assert "RECHAZO cn=ana motivo=bloqueado" in capsys.readouterr().out


def test_el_script_deja_pasar_sin_archivo(gancho, tmp_path, monkeypatch):
    monkeypatch.setattr(gancho, "ARCHIVO", str(tmp_path / "no-existe.json"))
    monkeypatch.setenv("common_name", "ana")
    with pytest.raises(SystemExit) as salida:
        gancho.main()
    assert salida.value.code == 0


def test_el_script_rechaza_con_un_archivo_ilegible(gancho, tmp_path, monkeypatch, capsys):
    archivo = tmp_path / "politicas.json"
    archivo.write_text("{a medias")
    monkeypatch.setattr(gancho, "ARCHIVO", str(archivo))
    monkeypatch.setenv("common_name", "ana")
    with pytest.raises(SystemExit) as salida:
        gancho.main()
    assert salida.value.code == 1
    assert "politica_ilegible" in capsys.readouterr().out


def test_el_script_no_se_fia_del_cn(gancho, monkeypatch, capsys):
    monkeypatch.setenv("common_name", "ana\nRECHAZO cn=otro")
    with pytest.raises(SystemExit):
        gancho.main()
    assert "cn=otro" not in capsys.readouterr().out


# ------------------------------------------------------------------ helper

SERVER_CONF = """\
port 1194
topology subnet
server 10.8.0.0 255.255.255.0 nopool
ifconfig-pool 10.8.0.2 10.8.0.191 255.255.255.0
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
secreto
-----END OpenVPN Static key V1-----
</tls-crypt>
client-connect /usr/local/lib/ovpn-web/client-connect
"""


@pytest.fixture
def cfg_helper(tmp_path):
    conf = tmp_path / "server.conf"
    conf.write_text(SERVER_CONF)
    return {"openvpn": {"server_conf": str(conf)}}


def test_server_conf_no_devuelve_claves_en_linea(helper, cfg_helper):
    resultado = helper.cmd_server_conf(cfg_helper)
    texto = json.dumps(resultado)
    assert "secreto" not in texto and "BEGIN" not in texto
    assert ["<tls-crypt>"] in resultado["directivas"]
    assert ["server", "10.8.0.0", "255.255.255.0", "nopool"] in resultado["directivas"]


def test_red_vpn_con_pool_explicito(helper, cfg_helper):
    red = helper.red_vpn(cfg_helper)
    assert str(red["red"]) == "10.8.0.0/24"
    assert [str(x) for x in red["pool"]] == ["10.8.0.2", "10.8.0.191"]
    assert red["topologia"] == "subnet"


def test_red_vpn_con_pool_implicito(helper, tmp_path):
    conf = tmp_path / "server.conf"
    conf.write_text("topology subnet\nserver 10.8.0.0 255.255.255.0\n")
    red = helper.red_vpn({"openvpn": {"server_conf": str(conf)}})
    # Lo que expande 'server' según su página de manual
    assert [str(x) for x in red["pool"]] == ["10.8.0.2", "10.8.0.253"]


@pytest.mark.parametrize("ip, mensaje", [
    ("10.8.0.100", "pool dinámico"),
    ("10.8.0.1", "no es una IP de cliente"),
    ("10.8.0.255", "no es una IP de cliente"),
    ("10.9.0.200", "no es una IP de cliente"),
])
def test_el_helper_rechaza_ips_fijas_inasignables(helper, cfg_helper, capsys, ip, mensaje):
    red = helper.red_vpn(cfg_helper)
    with pytest.raises(SystemExit):
        helper._validar_politica("ana", pol.normalizar({"ip_fija": ip}), red)
    assert mensaje in capsys.readouterr().err


def test_el_helper_acepta_una_ip_fuera_del_pool(helper, cfg_helper):
    red = helper.red_vpn(cfg_helper)
    helper._validar_politica("ana", pol.normalizar({"ip_fija": "10.8.0.200"}), red)


@pytest.mark.parametrize("politica", [
    {"ip_fija": "", "destinos": ["10.0.0.0/8"], "horario": [], "expira": "",
     "max_sesion_min": 0, "bloqueo": ""},
    {"ip_fija": "", "destinos": [], "horario": [{"dias": [0], "desde": "19:00", "hasta": "08:00"}],
     "expira": "", "max_sesion_min": 0, "bloqueo": ""},
    {"ip_fija": "", "destinos": [], "horario": [], "expira": "mañana",
     "max_sesion_min": 0, "bloqueo": ""},
    {"ip_fija": "", "destinos": [], "horario": [], "expira": "",
     "max_sesion_min": -1, "bloqueo": ""},
    {"ip_fija": "", "destinos": [], "horario": [], "expira": "", "max_sesion_min": 0,
     "bloqueo": "porque-si"},
    {"ip_fija": ""},
])
def test_el_helper_no_se_fia_de_la_politica(helper, politica):
    with pytest.raises(SystemExit):
        helper._validar_politica("ana", politica, None)


def test_reglas_nft(helper):
    texto, n = helper.reglas_nft({
        "ana": pol.normalizar({"ip_fija": "10.8.0.200",
                               "destinos": ["192.168.1.0/24", "192.168.1.10:443/tcp"]}),
        "luis": pol.normalizar({"ip_fija": "10.8.0.201"}),
    })
    assert n == 3
    assert "ip saddr 10.8.0.200 ip daddr 192.168.1.0/24 accept" in texto
    assert "ip saddr 10.8.0.200 ip daddr 192.168.1.10/32 tcp dport 443 accept" in texto
    assert "ip saddr 10.8.0.200 drop" in texto
    # Sin destinos no hay restricción, aunque tenga IP fija
    assert "10.8.0.201" not in texto
    # La misma restricción hacia el propio servidor que hacia la red
    assert "hook input" in texto and "hook forward" in texto
    assert texto.count("ip saddr 10.8.0.200 drop") == 2


def test_aplicar_politicas_sin_nft_ni_reglas(helper, cfg_helper, tmp_path, monkeypatch):
    """
    Sin destinos limitados no hace falta nftables: la instalación que solo usa
    horarios no tiene por qué tenerlo.
    """
    monkeypatch.setattr(helper, "DIR_POLITICAS", str(tmp_path / "ovpn-web"))
    monkeypatch.setattr(helper, "ARCHIVO_POLITICAS", str(tmp_path / "ovpn-web" / "politicas.json"))
    monkeypatch.setattr(helper.shutil, "which", lambda _: None)
    monkeypatch.setattr(helper.os, "chown", lambda *a: None)

    doc = pol.documento({"ana": {"ip_fija": "10.8.0.200", "horario": LABORABLES}}, 30)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(doc)))

    resultado = helper.cmd_aplicar_politicas(cfg_helper)

    assert resultado["ok"] and resultado["enganchado"] and resultado["nft"] == "sin_reglas"
    escrito = json.loads((tmp_path / "ovpn-web" / "politicas.json").read_text())
    assert escrito["mascara"] == "255.255.255.0"
    assert escrito["clientes"]["ana"]["ip_fija"] == "10.8.0.200"


def test_aplicar_politicas_con_destinos_exige_nft(helper, cfg_helper, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(helper, "DIR_POLITICAS", str(tmp_path / "ovpn-web"))
    monkeypatch.setattr(helper, "ARCHIVO_POLITICAS", str(tmp_path / "ovpn-web" / "politicas.json"))
    monkeypatch.setattr(helper.shutil, "which", lambda _: None)

    doc = pol.documento({"ana": {"ip_fija": "10.8.0.200", "destinos": ["192.168.1.0/24"]}}, 0)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(doc)))

    with pytest.raises(SystemExit):
        helper.cmd_aplicar_politicas(cfg_helper)
    assert "nft" in capsys.readouterr().err
    # Nada escrito: una restricción de destinos que no se aplica es peor que ninguna
    assert not (tmp_path / "ovpn-web" / "politicas.json").exists()


def test_aplicar_politicas_rechaza_documentos_ajenos(helper, cfg_helper, monkeypatch):
    for bruto in ("no es json", json.dumps({"version": 99, "global": {}, "clientes": {}}),
                  json.dumps({"version": 1, "global": {"max_sesion_min": 0},
                              "clientes": {"../etc": pol.vacia()}})):
        monkeypatch.setattr(sys, "stdin", io.StringIO(bruto))
        with pytest.raises(SystemExit):
            helper.cmd_aplicar_politicas(cfg_helper)
