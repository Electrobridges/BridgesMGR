"""
Integridad entre plantillas y rutas.

Existe por un fallo real: las pestañas de Auditoría apuntaban a /auditoria
cuando el router lleva prefijo /admin. El panel se veía perfecto y los enlaces
daban 404, porque una URL escrita a mano en una plantilla no la comprueba nadie
—ni Python, ni Jinja, ni el navegador hasta que alguien pulsa.

Esto recorre TODAS las plantillas, saca todos los destinos y comprueba que la
aplicación los reconoce. Sin sesión, una ruta que existe responde 401, 403, 303
o 422; solo una que no existe responde 404. Con eso basta y no hace falta
autenticarse.
"""

import re
from pathlib import Path

import pytest

PLANTILLAS = Path(__file__).resolve().parents[1] / "app" / "templates"

# Qué atributo implica qué método
FUENTES = [
    (r'href="(/[^"#]*)"', "GET"),
    (r'hx-get="(/[^"]*)"', "GET"),
    (r'hx-post="(/[^"]*)"', "POST"),
    (r'action="(/[^"]*)"', "POST"),
]


def _destinos():
    """Todos los (url, método, plantilla) que aparecen en las plantillas"""
    encontrados = []
    for archivo in sorted(PLANTILLAS.rglob("*.html")):
        texto = archivo.read_text(encoding="utf-8")
        for patron, metodo in FUENTES:
            for m in re.finditer(patron, texto):
                url = m.group(1)
                if url.startswith("/static"):
                    continue
                # Un {{ ... }} de Jinja se sustituye por un segmento válido:
                # lo que se comprueba es la forma de la ruta, no el valor.
                prueba = re.sub(r'\{\{[^}]*\}\}', 'x', url).replace("&amp;", "&")
                encontrados.append((prueba, metodo, archivo.name))
    return sorted(set(encontrados))


DESTINOS = _destinos()


def test_hay_destinos_que_comprobar():
    """Si el barrido deja de encontrar nada, la prueba no estaría probando nada"""
    assert len(DESTINOS) > 20


@pytest.mark.parametrize("url,metodo,plantilla", DESTINOS,
                         ids=["%s %s" % (m, u) for u, m, _ in DESTINOS])
def test_el_destino_existe(cliente, url, metodo, plantilla):
    respuesta = cliente.request(metodo, url, follow_redirects=False)

    assert respuesta.status_code != 404, (
        "%s enlaza a %s %s y no hay ninguna ruta que lo atienda" % (plantilla, metodo, url)
    )
