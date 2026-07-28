"""
Segundo factor TOTP.

Lo importante aquí son los vectores de prueba de la RFC 6238: si el código
generado no coincide con ellos, las apps de autenticación tampoco coincidirán
con nosotros, y eso se descubre tarde y mal.
"""

import base64

import pytest

from app.core import totp

# Secreto de los vectores oficiales de la RFC 6238: los ASCII "12345678901234567890"
SECRETO_RFC = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")


@pytest.mark.parametrize("momento,esperado", [
    (59,          "287082"),
    (1111111109,  "081804"),
    (1111111111,  "050471"),
    (1234567890,  "005924"),
    (2000000000,  "279037"),
    (20000000000, "353130"),
])
def test_vectores_de_la_rfc_6238(momento, esperado):
    """
    La RFC publica los códigos de 8 dígitos; nosotros usamos 6, que son sus
    seis últimos (truncar a 10^6 en vez de a 10^8).
    """
    assert totp.codigo(SECRETO_RFC, momento=momento) == esperado


def test_secreto_generado_es_base32_utilizable():
    secreto = totp.generar_secreto()

    assert len(secreto) == 32                 # 20 bytes -> 32 caracteres exactos
    assert "=" not in secreto                 # las apps lo esperan sin relleno
    assert totp.codigo(secreto).isdigit()


def test_dos_secretos_nunca_coinciden():
    assert totp.generar_secreto() != totp.generar_secreto()


def test_verifica_el_codigo_del_momento():
    secreto = totp.generar_secreto()
    assert totp.verificar(secreto, totp.codigo(secreto)) == totp.paso_actual()


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_tolera_un_paso_de_desfase(delta):
    """±30 s de diferencia entre el reloj del servidor y el del móvil"""
    secreto = totp.generar_secreto()
    paso = totp.paso_actual() + delta

    assert totp.verificar(secreto, totp.codigo(secreto, paso=paso)) == paso


@pytest.mark.parametrize("delta", [-2, 2, 10, -60])
def test_rechaza_mas_alla_de_la_ventana(delta):
    secreto = totp.generar_secreto()
    paso = totp.paso_actual() + delta

    assert totp.verificar(secreto, totp.codigo(secreto, paso=paso)) is None


def test_un_codigo_no_se_puede_reutilizar():
    """
    Sin esto, un código interceptado sirve durante toda su ventana. Quien
    llama guarda el paso aceptado y lo pasa como paso_minimo la vez siguiente.
    """
    secreto = totp.generar_secreto()
    entrada = totp.codigo(secreto)

    paso = totp.verificar(secreto, entrada)
    assert paso is not None

    assert totp.verificar(secreto, entrada, paso_minimo=paso) is None


def test_no_acepta_el_codigo_de_otro_secreto():
    a, b = totp.generar_secreto(), totp.generar_secreto()
    assert totp.verificar(a, totp.codigo(b)) is None


@pytest.mark.parametrize("entrada", ["", "12345", "1234567", "abcdef", None, 123456])
def test_entradas_que_no_son_un_codigo(entrada):
    assert totp.verificar(totp.generar_secreto(), entrada) is None


def test_acepta_el_codigo_con_espacios():
    """Las apps lo muestran como '123 456' y la gente lo copia tal cual"""
    secreto = totp.generar_secreto()
    entrada = totp.codigo(secreto)

    assert totp.verificar(secreto, entrada[:3] + " " + entrada[3:]) is not None


@pytest.mark.parametrize("secreto", ["", "   ", "no-es-base32!", None, 12345])
def test_secretos_mal_formados(secreto):
    with pytest.raises(totp.TOTPInvalido):
        totp.codigo(secreto)


def test_secreto_en_minusculas_y_con_relleno():
    """Tal como lo pega alguien desde un gestor de contraseñas"""
    secreto = totp.generar_secreto()
    assert totp.codigo(secreto.lower()) == totp.codigo(secreto)
    assert totp.codigo(secreto + "======") == totp.codigo(secreto)


def test_uri_otpauth():
    uri = totp.uri_otpauth("JBSWY3DPEHPK3PXP", "daniel")

    assert uri.startswith("otpauth://totp/OpenVPN%20Manager%3Adaniel?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=OpenVPN+Manager" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_uri_escapa_nombres_raros():
    uri = totp.uri_otpauth("JBSWY3DPEHPK3PXP", "usuario con espacio")
    assert " " not in uri


def test_formatear_secreto_para_teclearlo():
    assert totp.formatear_secreto("JBSWY3DPEHPK3PXP") == "JBSW Y3DP EHPK 3PXP"
