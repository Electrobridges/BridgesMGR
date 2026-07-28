"""
Invariantes de las dependencias.

Lo que se instala en un servidor es requirements.txt, un lock con versiones
exactas y el SHA-256 de cada artefacto. Estas pruebas vigilan que ese lock siga
mereciendo confianza: que lleve hashes, que no se edite a mano, y que los
rangos declarados no se contradigan entre archivos.

Lo que NO se comprueba aquí es si el lock está al día respecto a los .in: eso
exige resolver contra PyPI y vive en la CI, que tiene red.
"""

import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]

LOCKS = ["requirements.txt", "requirements-dev.txt"]
FUENTES = ["requirements.in", "requirements-dev.in"]


def _leer(nombre):
    ruta = RAIZ / nombre
    assert ruta.is_file(), "Falta %s" % nombre
    return ruta.read_text(encoding="utf-8")


def _paquetes_de(texto):
    """{nombre: especificador} de un archivo .in, ignorando comentarios y -r"""
    paquetes = {}
    for linea in texto.splitlines():
        linea = linea.split("#")[0].strip()
        if not linea or linea.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*(.*)$", linea)
        if m:
            paquetes[m.group(1).lower().replace("_", "-")] = m.group(2).replace(" ", "")
    return paquetes


@pytest.mark.parametrize("lock", LOCKS)
def test_el_lock_lleva_hashes(lock):
    """
    Sin hashes, el lock da reproducibilidad pero no integridad: si un espejo de
    PyPI devuelve otro artefacto con la misma versión, pip lo instala tan
    contento. Con ellos, `pip install --require-hashes` aborta.
    """
    texto = _leer(lock)

    fijados = re.findall(r"^([A-Za-z0-9._-]+)==", texto, re.M)
    assert fijados, "%s no fija ninguna versión" % lock

    sin_hash = [p for p in fijados if not re.search(
        r"^%s==[^\n]*\n(?:\s*--hash=sha256:)" % re.escape(p), texto, re.M)]
    assert not sin_hash, "Sin hash en %s: %s" % (lock, ", ".join(sin_hash))


def test_el_lock_cubre_linux_y_no_solo_la_maquina_de_quien_lo_genero():
    """
    Sin --universal, uv resuelve para el sistema donde corre. Generado en
    Windows sale sin uvloop —uvicorn[standard] lo excluye allí— y el servidor
    Linux se queda sin él: uvicorn cae al bucle asyncio estándar, más lento,
    sin que nada falle ni lo diga. El lock dejaría de ser reproducible y pasaría
    a depender de quién lo generó.
    """
    texto = _leer("requirements.txt")

    assert re.search(r"^uvloop==", texto, re.M), (
        "Falta uvloop: el lock no se generó con --universal"
    )
    assert "sys_platform" in texto, (
        "El lock no lleva marcadores de plataforma; regenéralo con --universal"
    )


@pytest.mark.parametrize("lock", LOCKS)
def test_el_lock_no_se_edita_a_mano(lock):
    """Se genera de su .in; un cambio a mano se pierde en la siguiente vez"""
    assert "No edites" in _leer(lock.replace(".txt", ".in")), (
        "%s debe avisar de que el .txt se genera" % lock.replace(".txt", ".in")
    )


@pytest.mark.parametrize("fuente", FUENTES)
def test_todo_rango_tiene_techo(fuente):
    """
    Un `>=` sin techo deja que una instalación de mañana traiga una versión
    mayor que nadie probó contra este código. En un panel que revoca
    certificados eso no es una molestia: es una incidencia en producción.
    """
    sin_techo = [
        nombre for nombre, spec in _paquetes_de(_leer(fuente)).items()
        if spec and "<" not in spec
    ]
    assert not sin_techo, "Sin versión máxima en %s: %s" % (fuente, ", ".join(sin_techo))


def test_pyproject_y_requirements_dicen_lo_mismo():
    """
    Dos sitios declaran los rangos y no pueden contradecirse: pyproject.toml es
    lo que ve quien instala el paquete, requirements.in lo que alimenta el lock
    del servidor. Si divergen, hay dos verdades sobre qué versiones valen.
    """
    pyproject = _leer("pyproject.toml")

    bloque = re.search(r"^dependencies = \[(.*?)^\]", pyproject, re.M | re.S)
    assert bloque, "No se encuentra 'dependencies' en pyproject.toml"

    declarados = _paquetes_de(
        "\n".join(l.strip().strip('",') for l in bloque.group(1).splitlines())
    )
    pedidos = _paquetes_de(_leer("requirements.in"))

    assert declarados == pedidos, (
        "pyproject.toml y requirements.in no coinciden.\n"
        "  solo en pyproject: %s\n"
        "  solo en requirements.in: %s\n"
        "  con rango distinto: %s"
        % (
            sorted(set(declarados) - set(pedidos)),
            sorted(set(pedidos) - set(declarados)),
            sorted(n for n in set(declarados) & set(pedidos)
                   if declarados[n] != pedidos[n]),
        )
    )


# ------------------------------------------------------------------ licencia

def test_la_licencia_dice_lo_mismo_en_todas_partes():
    """
    La licencia se declara en cinco sitios. Si divergen, quien instale el
    paquete lee una cosa y quien clone el repo otra — y en algo que da derechos
    de uso, eso no es un detalle cosmético.
    """
    esperado = "Apache"

    licencia = _leer("LICENSE")
    assert "Apache License" in licencia and "Version 2.0" in licencia
    assert "Copyright 2026 Daniel Puentes" in licencia, "LICENSE sin titular"

    assert '__license__ = "Apache-2.0"' in _leer("app/__init__.py")

    pyproject = _leer("pyproject.toml")
    assert 'license = { text = "Apache-2.0" }' in pyproject
    assert "License :: OSI Approved :: Apache Software License" in pyproject

    for doc in ("README.md", "PRODUCT.md"):
        assert esperado in _leer(doc), "%s no menciona la licencia" % doc


def test_existe_el_notice_con_la_marca():
    """
    Apache 2.0 obliga a los derivados a conservar el NOTICE. Es donde la
    atribución y la reserva de marca viajan con el código: la sección 6 no
    concede derecho sobre 'BridgesMGR', y eso tiene que estar escrito.
    """
    notice = _leer("NOTICE")

    assert "Copyright 2026" in notice
    assert "BridgesMGR" in notice and "marcas" in notice.lower()
    # El material de terceros que ya se distribuye en el repo
    assert "Poppins" in notice
    assert "Material Design Icons" in notice
