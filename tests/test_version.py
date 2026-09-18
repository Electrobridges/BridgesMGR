"""
La versión se declara en un solo sitio, o en varios que no pueden discrepar.

Existe por un fallo real: `__version__` se quedó en 0.1.0 mientras
`pyproject.toml` decía 0.2.0 y el tag `v0.2.0` apuntaba a un commit de agosto,
con 18 commits detrás sin etiquetar. Cuando hubo que saber qué versión corría
el servidor de producción, la única vía fue comparar los hashes del árbol
instalado contra la historia de git. Una cadena de versión que no se puede
creer es peor que ninguna.

Y el changelog se cierra en el mismo commit que sube la versión: si
`__version__` dice X, el changelog tiene que tener una sección [X].
"""

import re
from pathlib import Path

import app

RAIZ = Path(__file__).resolve().parents[1]


def _leer(nombre):
    return (RAIZ / nombre).read_text(encoding="utf-8")


def test_la_version_del_modulo_y_del_paquete_coinciden():
    m = re.search(r'^version = "([^"]+)"$', _leer("pyproject.toml"), re.M)
    assert m, "No se encuentra 'version' en pyproject.toml"
    assert m.group(1) == app.__version__, (
        "pyproject.toml dice %s y app.__version__ dice %s"
        % (m.group(1), app.__version__)
    )


def test_la_version_es_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", app.__version__), app.__version__


def test_el_changelog_tiene_cerrada_la_version_actual():
    """
    Subir la versión sin cerrar su sección en el changelog deja un tag que no
    dice qué trae. Y al revés: una sección cerrada con una versión que el
    código no declara es un changelog que miente.
    """
    encabezado = "## [%s]" % app.__version__
    assert encabezado in _leer("CHANGELOG.md"), (
        "CHANGELOG.md no tiene la sección '%s'" % encabezado
    )


def test_el_cli_dice_la_version(capsys):
    """`python -m app.cli --version` es la vía sin navegador ni sesión"""
    import pytest
    from app import cli

    with pytest.raises(SystemExit) as salida:
        cli.main(["--version"])
    assert salida.value.code == 0
    assert app.__version__ in capsys.readouterr().out


def test_el_panel_enseña_la_version_dentro(cliente, como_admin):
    """Con sesión se ve en todas las páginas, sin abrir una terminal"""
    assert "BridgesMGR %s" % app.__version__ in cliente.get("/").text


def test_la_pagina_de_entrada_no_dice_la_version(cliente):
    """A quien aún no ha entrado no se le cuenta qué versión hay"""
    respuesta = cliente.get("/login")
    assert respuesta.status_code == 200
    assert app.__version__ not in respuesta.text
