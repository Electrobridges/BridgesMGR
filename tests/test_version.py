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
