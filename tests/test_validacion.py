"""
Validación de Common Names.

Es la frontera de seguridad: estos nombres acaban en argumentos de easyrsa
ejecutado como root y en rutas dentro de la PKI.
"""

import pytest

from app.core.validacion import CNInvalido, es_cn_valido, validar_cn


@pytest.mark.parametrize("cn", [
    "daniel",
    "administrador-daniel",
    "portatil.oficina",
    "usuario_1",
    "a1",
    "a",                      # un solo carácter alfanumérico es aceptable
    "A" * 64,
])
def test_nombres_validos(cn):
    assert validar_cn(cn) == cn


@pytest.mark.parametrize("cn", [
    "",
    "   ",
    "-empieza-con-guion",
    "termina-con-guion-",
    ".punto-inicial",
    "con espacio",
    "con/barra",
    "../../etc/passwd",       # travesía de rutas
    "cliente;rm -rf /",       # inyección de comandos
    "cliente$(whoami)",
    "cliente`id`",
    "cliente\nkill server",   # inyección en el protocolo del management
    "cliente\ttab",
    "--pki-dir=/tmp",         # que no se cuele como opción de easyrsa
    "A" * 65,                 # demasiado largo
    "cliente|otro",
    "cliente&fondo",
])
def test_nombres_rechazados(cn):
    with pytest.raises(CNInvalido):
        validar_cn(cn)


@pytest.mark.parametrize("cn", ["server", "SERVER", "Server", "ca", "CA"])
def test_nombres_reservados(cn):
    """Nunca se debe poder revocar el certificado del propio servidor"""
    with pytest.raises(CNInvalido):
        validar_cn(cn)


def test_recorta_espacios():
    assert validar_cn("  daniel  ") == "daniel"


def test_tipos_no_texto():
    for valor in (None, 123, ["daniel"]):
        with pytest.raises(CNInvalido):
            validar_cn(valor)


def test_version_booleana():
    assert es_cn_valido("daniel")
    assert not es_cn_valido("con espacio")
