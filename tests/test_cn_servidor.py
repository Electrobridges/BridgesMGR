"""
Exclusión del certificado del propio servidor de la lista de clientes.

El certificado con el que OpenVPN se identifica vive en la misma PKI que los de
cliente, así que el panel lo listaba como uno más, con su botón de revocar al
lado. RESERVADOS no lo atrapaba: compara exacto contra {'server', 'ca'} y los
instaladores al uso generan nombres con sufijo aleatorio, del tipo
'server_SU1O2eUJ8SUV0x2W'.

Estas pruebas cargan el helper como módulo, a diferencia del resto de
test_despliegue.py, que lo lee como texto: aquí hay lógica que ejecutar, no solo
estructura que comprobar. Importarlo es seguro porque main() está bajo
if __name__ == "__main__".
"""

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
HELPER = RAIZ / "deploy" / "ovpn-web-helper"


@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_loader(
        "ovpn_web_helper",
        importlib.machinery.SourceFileLoader("ovpn_web_helper", str(HELPER)),
    )
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _cert(directorio, nombre, cn):
    """Certificado autofirmado de usar y tirar, solo para leerle el CN"""
    ruta = directorio / nombre
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(directorio / "tmp.key"), "-out", str(ruta),
         "-days", "1", "-subj", "/CN=%s" % cn],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return ruta


sin_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="requiere openssl en el PATH"
)


# ------------------------------------------------------- el filtro en sí

def test_reservados_siguen_filtrando(helper):
    """Lo que ya funcionaba tiene que seguir funcionando sin CN de servidor"""
    assert helper._es_del_servidor("server", None)
    assert helper._es_del_servidor("CA", None)
    assert not helper._es_del_servidor("daniel", None)


def test_el_cn_real_del_servidor_queda_fuera(helper):
    propio = "server_SU1O2eUJ8SUV0x2W"

    assert helper._es_del_servidor(propio, propio)
    # Sin conocerlo se colaba: es exactamente el fallo que se corrige
    assert not helper._es_del_servidor(propio, None)


def test_la_comparacion_no_distingue_mayusculas(helper):
    assert helper._es_del_servidor("SERVER_ABC", "server_abc")


def test_un_cliente_legitimo_no_se_confunde_con_el_servidor(helper):
    """
    'server-madrid' es un nombre de cliente perfectamente válido.

    Por eso la exclusión no puede ser por prefijo: tiene que ser el CN exacto
    que declara el server.conf.
    """
    assert not helper._es_del_servidor("server-madrid", "server_SU1O2eUJ8SUV0x2W")


# ------------------------------------------- de dónde sale el CN del servidor

def test_declarado_en_config_no_toca_el_disco(helper):
    cfg = {"openvpn": {"cn_servidor": "mi-servidor", "server_conf": "/no/existe"}}
    assert helper.cn_del_servidor(cfg) == "mi-servidor"


def test_sin_nada_que_leer_devuelve_none(helper, tmp_path):
    """
    Degrada a RESERVADOS en vez de reventar.

    Es una capa por encima del filtro de siempre, no un sustituto: si no hay
    forma de averiguar el CN, listar tiene que seguir funcionando.
    """
    cfg = {"openvpn": {"server_conf": str(tmp_path / "no-existe.conf")}}
    assert helper.cn_del_servidor(cfg) is None


@sin_openssl
def test_lo_deduce_del_certificado_del_server_conf(helper, tmp_path):
    _cert(tmp_path, "servidor.crt", "server_SU1O2eUJ8SUV0x2W")
    conf = tmp_path / "server.conf"
    conf.write_text("port 1194\ncert %s\n" % (tmp_path / "servidor.crt"), encoding="utf-8")

    cfg = {"openvpn": {"server_conf": str(conf)}}
    assert helper.cn_del_servidor(cfg) == "server_SU1O2eUJ8SUV0x2W"


@sin_openssl
def test_resuelve_las_rutas_relativas_del_server_conf(helper, tmp_path):
    """
    Las rutas del server.conf pueden ser relativas y hay que resolverlas.

    OpenVPN lo hace contra su directorio de trabajo, que la unidad fija con --cd
    al del propio archivo. Es el caso real de las instalaciones hechas con los
    scripts al uso: 'cert server_XXXX.crt' a secas. Sin resolverlo, el
    certificado se busca donde no está y el CN del servidor vuelve a colarse en
    la lista.
    """
    _cert(tmp_path, "servidor.crt", "server_relativo")
    conf = tmp_path / "server.conf"
    conf.write_text("cert servidor.crt\n", encoding="utf-8")

    cfg = {"openvpn": {"server_conf": str(conf)}}
    assert helper.cn_del_servidor(cfg) == "server_relativo"


@sin_openssl
def test_una_ruta_mal_declarada_cae_a_la_deteccion_automatica(helper, tmp_path, monkeypatch):
    """Una errata en la clave no puede dejar el resultado peor que no ponerla"""
    _cert(tmp_path, "servidor.crt", "server_detectado")
    estandar = tmp_path / "server.conf"
    estandar.write_text("cert servidor.crt\n", encoding="utf-8")
    monkeypatch.setattr(helper, "SERVER_CONF_ESTANDAR", (str(estandar),))

    cfg = {"openvpn": {"server_conf": "/ruta/con/errata.conf"}}
    assert helper.cn_del_servidor(cfg) == "server_detectado"


def test_server_conf_sin_directiva_cert(helper, tmp_path):
    conf = tmp_path / "server.conf"
    conf.write_text("port 1194\nproto udp\n", encoding="utf-8")

    cfg = {"openvpn": {"server_conf": str(conf)}}
    assert helper.cn_del_servidor(cfg) is None


# ------------------------------------------------------- el efecto en listar

def _pki_falsa(tmp_path, validos, revocados=()):
    """PKI mínima: lo que mira cmd_listar es issued/ e index.txt"""
    base = tmp_path / "easy-rsa"
    (base / "pki" / "issued").mkdir(parents=True)

    for cn in validos:
        (base / "pki" / "issued" / ("%s.crt" % cn)).write_text("", encoding="utf-8")

    lineas = ["R\t281031231908Z\t260729232130Z\tAABB\tunknown\t/CN=%s\n" % cn
              for cn in revocados]
    (base / "pki" / "index.txt").write_text("".join(lineas), encoding="utf-8")
    return base


@sin_openssl
def test_listar_no_devuelve_el_certificado_del_servidor(helper, tmp_path):
    """
    La prueba del fallo: el panel enseñaba el certificado del servidor como un
    cliente más, con sus botones de revocar y descargar.
    """
    propio = "server_SU1O2eUJ8SUV0x2W"
    base = _pki_falsa(tmp_path, validos=[propio, "daniel", "server-madrid"],
                      revocados=["antiguo"])

    _cert(tmp_path, "servidor.crt", propio)
    conf = tmp_path / "server.conf"
    conf.write_text("cert servidor.crt\n", encoding="utf-8")

    cfg = {"openvpn": {"easyrsa_path": str(base), "server_conf": str(conf)}}
    resultado = helper.cmd_listar(cfg)

    assert propio not in resultado["validos"]
    # Y no se lleva por delante a los clientes de verdad, ni al que se le parece
    assert resultado["validos"] == ["daniel", "server-madrid"]
    assert resultado["revocados"] == ["antiguo"]


def test_listar_sigue_funcionando_sin_poder_deducir_el_cn(helper, tmp_path):
    """Sin server.conf que leer, se degrada al filtro de siempre"""
    base = _pki_falsa(tmp_path, validos=["daniel", "server"])

    cfg = {"openvpn": {"easyrsa_path": str(base),
                       "server_conf": str(tmp_path / "no-existe.conf")}}
    resultado = helper.cmd_listar(cfg)

    assert resultado["validos"] == ["daniel"]
