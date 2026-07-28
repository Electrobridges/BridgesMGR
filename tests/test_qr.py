"""
Código QR del alta del segundo factor.

Que un QR escanee no se puede comprobar sin un móvil delante, así que aquí se
verifica lo que sí es verificable: que se genera, que cabe el caso peor, que
llega a la página en un formato que la CSP admite, y que no aparece donde no
debe.
"""

import base64
import re

import pytest

from app import db, qr
from app.core import totp

from .test_dos_factores import csrf_de, dar_de_alta


def svg_de(data_uri):
    assert data_uri.startswith("data:image/svg+xml;base64,")
    return base64.b64decode(data_uri.split(",", 1)[1]).decode("utf-8")


def lado_en_modulos(svg):
    """Módulos por lado, deduciendo del viewBox la escala y el borde"""
    lado = int(re.search(r'viewBox="0 0 (\d+)', svg).group(1))
    return lado // 5 - 2 * 3            # escala 5, borde 3 a cada lado


def test_se_genera_un_svg():
    svg = svg_de(qr.data_uri("otpauth://totp/prueba?secret=JBSWY3DPEHPK3PXP"))

    assert svg.startswith("<svg")
    assert "http://www.w3.org/2000/svg" in svg


def test_no_referencia_nada_de_fuera():
    """
    Un QR que pidiera algo a la red rompería la CSP y delataría al usuario.
    Debe ser autocontenido.
    """
    svg = svg_de(qr.data_uri("otpauth://totp/prueba?secret=JBSWY3DPEHPK3PXP"))

    for prohibido in ("http://", "https://", "<script", "xlink:href", "<image"):
        assert prohibido not in svg.replace("http://www.w3.org/2000/svg", "")


@pytest.mark.parametrize("largo", [1, 6, 32, 64])
def test_cabe_el_nombre_de_usuario_mas_largo(largo):
    """
    validar_cn admite hasta 64 caracteres; el QR tiene que aguantar ese caso
    peor sin quedarse sin capacidad.
    """
    uri = totp.uri_otpauth(totp.generar_secreto(), "u" * largo)
    svg = svg_de(qr.data_uri(uri))

    modulos = lado_en_modulos(svg)
    version = (modulos - 17) // 4

    assert 1 <= version <= 10, "versión %d inesperada para %d caracteres" % (version, largo)
    assert modulos == 4 * version + 17


def test_dos_secretos_dan_dos_qr_distintos():
    a = qr.data_uri(totp.uri_otpauth(totp.generar_secreto(), "daniel"))
    b = qr.data_uri(totp.uri_otpauth(totp.generar_secreto(), "daniel"))
    assert a != b


def test_hay_generador_de_qr_instalado():
    """Si esto falla, falta 'pip install -r requirements.txt'"""
    assert qr.disponible()


# ------------------------------------------------------------- en la página

def test_el_alta_muestra_el_qr(como_admin, cfg):
    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    r = como_admin.post("/perfil/totp/iniciar", headers=cab)

    assert 'src="data:image/svg+xml;base64,' in r.text
    assert "Escanéalo con la app" in r.text


def test_el_qr_lleva_texto_alternativo(como_admin, cfg):
    """Sin alt, quien no ve la imagen no sabe que ahí hay algo"""
    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    r = como_admin.post("/perfil/totp/iniciar", headers=cab)

    assert re.search(r'<img[^>]+alt="[^"]{10,}"', r.text)


def test_sigue_estando_la_clave_para_teclearla(como_admin, cfg, usuarios):
    """El QR no debe ser la única vía: hay quien da de alta a mano"""
    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    r = como_admin.post("/perfil/totp/iniciar", headers=cab)

    secreto = db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["totp_secret"]
    assert totp.formatear_secreto(secreto) in r.text


def test_el_qr_desaparece_al_confirmar(como_admin, cfg, usuarios):
    """Es el secreto en otro formato: no debe sobrevivir al alta"""
    dar_de_alta(como_admin, cfg, usuarios["admin"])

    assert "data:image/svg+xml" not in como_admin.get("/perfil").text


def test_sin_generador_se_avisa_y_se_puede_seguir(como_admin, cfg, usuarios, monkeypatch):
    """
    Si falta el paquete, nada de dejar un hueco mudo: se dice qué pasa y el
    alta sigue siendo posible tecleando la clave.
    """
    monkeypatch.setattr(qr, "segno", None)

    cab = {"X-CSRF-Token": csrf_de(como_admin, cfg)}
    r = como_admin.post("/perfil/totp/iniciar", headers=cab)

    assert r.status_code == 200
    assert "data:image/svg+xml" not in r.text
    assert "segno" in r.text

    secreto = db.obtener_usuario(cfg.seguridad.db_path, usuarios["admin"])["totp_secret"]
    assert totp.formatear_secreto(secreto) in r.text
