"""
Enlaces y anclas de la documentación.

La documentación tiene enlaces relativos en bastante más sitios de los que
parece: el índice de la wiki salta a un apartado de la documentación, cada
página de la wiki enlaza la anterior y la siguiente, el README baja a las
capturas y a las páginas en inglés. Un enlace roto no rompe la CI ni ninguna
otra prueba —se ve en el repo publicado, que es donde ya no se mira—, así que
esto los recorre todos y los comprueba.

Son comprobaciones de texto sobre los archivos, deliberadamente literales: si
una de estas pruebas falla, casi siempre hay un enlace roto de verdad y lo que
hay que arreglar es el enlace.
"""

import re
import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]

# Lo que se mira, en cualquier parte de un .md: destinos de enlaces Markdown y
# de imágenes. El `srcset` se separa aparte porque su atributo son varias rutas
# con su descriptor —«hero-400.jpg 400w, hero-800.jpg 800w»— y no una sola.
_ENLACE = re.compile(r"\]\(\s*([^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)")
_ATRIBUTO = re.compile(r"\b(?:src|srcset)=\"([^\"]+)\"")

# Lo que no es un archivo del repo: esquemas que no tocan el disco.
_EXTERNO = ("http://", "https://", "mailto:", "tel:", "data:", "//")

# Una valla de bloque de código. Lo que hay dentro no es Markdown: un `#` de
# comentario de shell no es un encabezado, y sus líneas no generan anclas.
_VALLA = re.compile(r"^\s*(?:```|~~~)")

# Encabezado de ATX: hasta seis almohadillas seguidas de texto.
_ENCABEZADO = re.compile(r"^(#{1,6})\s+(.*)$")

# Un enlace dentro del texto de otro enlace, para quedarse con lo que se ve:
# «## [Clientes](clientes.md)» genera el ancla «clientes», no «clientesmd».
_ENLACE_EN_TEXTO = re.compile(r"\[([^\]]*)\]\([^)]*\)")

# Lo que se quita del texto antes de convertirlo en ancla: el identificador
# explícito de Jekyll al final, y las dos marcas de énfasis que GitHub quita.
# El guion bajo NO se quita, porque es carácter de palabra y GitHub lo
# conserva: «## `max_intentos_login`» va a `#max_intentos_login`.
_IDENTIFICADOR = re.compile(r"\s*\{[.#][^}]*\}\s*$")
_MARCAS = str.maketrans("", "", "`*")


def _markdown():
    """
    Los .md versionados, y solo ellos.

    Se pregunta a git en vez de recorrer el directorio porque «los .md del
    repositorio» son los versionados: recorrer el árbol mezclaría las carpetas
    de trabajo locales que no se suben, y la prueba fallaría por archivos que
    no son del proyecto.
    """
    salida = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=str(RAIZ), capture_output=True, text=True, check=True,
    )
    return [RAIZ / linea for linea in salida.stdout.splitlines() if linea.strip()]


def _ancla(encabezado):
    """
    El ancla que GitHub le da a un encabezado.

    Minúsculas; fuera las marcas de énfasis, los signos de puntuación y los
    emojis; los espacios, guiones. Las letras con tilde se conservan, que es lo
    que hace GitHub: «## Cómo se aplican» va a `#cómo-se-aplican».

    Lo que NO se hace es recortar el resultado antes de cambiar los espacios por
    guiones, y es a propósito. En «## 🚀 Instalación rápida» el emoji se va y
    deja un espacio delante, y ese espacio es un guion más: el ancla es
    `-instalación-rápida`, con el guion delante. Recortar daría
    «instalación-rápida» y daría por roto un enlace que GitHub resuelve bien.
    """
    texto = _ENLACE_EN_TEXTO.sub(r"\1", encabezado)
    texto = _IDENTIFICADOR.sub("", texto)
    texto = texto.translate(_MARCAS).lower()
    texto = re.sub(r"[^\w\s-]", "", texto, flags=re.UNICODE)
    return re.sub(r"\s+", "-", texto)


def _anclas(path):
    """Todos los anclas que declara un archivo, duplicados incluidos."""
    dentro = False
    vistos = {}
    salida = set()

    for linea in path.read_text(encoding="utf-8").splitlines():
        if _VALLA.match(linea):
            dentro = not dentro
            continue
        if dentro:
            continue

        encabezado = _ENCABEZADO.match(linea)
        if not encabezado:
            continue

        ancla = _ancla(encabezado.group(2).rstrip())
        if not ancla:
            continue

        # GitHub no repite: un encabezado repetido añade -1, -2, -3.
        repeticiones = vistos.get(ancla, 0)
        vistos[ancla] = repeticiones + 1
        salida.add(ancla if not repeticiones else "%s-%d" % (ancla, repeticiones))

    return salida


def _destinos(texto):
    """Las rutas que cita un archivo: enlaces Markdown, src y srcset."""
    citados = [m.group(1) for m in _ENLACE.finditer(texto)]

    for atributo in _ATRIBUTO.finditer(texto):
        valor = atributo.group(1)
        # El srcset son varias rutas con su descriptor; cada entrada empieza por
        # la ruta y lo que sobra es «400w» o «2x».
        citados.extend(entrada.strip().split()[0]
                       for entrada in valor.split(",") if entrada.strip())

    return citados


def _ruta_de(destino):
    """La parte de un destino que es una ruta, sin ancla ni query."""
    ruta = destino.split("#", 1)[0].split("?", 1)[0].strip()
    if not ruta or ruta.startswith("#") or ruta.startswith(_EXTERNO):
        return None
    return ruta


@pytest.mark.parametrize("path", _markdown(), ids=lambda p: p.name)
def test_cada_enlace_relativo_apunta_a_un_archivo_que_existe(path):
    rotas = []

    for destino in _destinos(path.read_text(encoding="utf-8")):
        ruta = _ruta_de(destino)
        if ruta and not (path.parent / ruta).exists():
            rotas.append(destino)

    assert not rotas, "Enlaces a archivos que no existen en %s: %s" % (
        path.relative_to(RAIZ), ", ".join(sorted(set(rotas))))


@pytest.mark.parametrize("path", _markdown(), ids=lambda p: p.name)
def test_cada_ancla_existe_en_el_archivo_de_destino(path):
    rotas = []

    for destino in _destinos(path.read_text(encoding="utf-8")):
        ruta, _, ancla = destino.partition("#")
        if not ancla:
            continue

        ancla = ancla.lower()
        if not ruta:  # #ancla dentro de la misma página
            objetivo = path
        else:
            limpio = ruta.split("?", 1)[0].strip()
            if not limpio or limpio.startswith(_EXTERNO):
                continue
            objetivo = path.parent / limpio
            if not objetivo.exists():
                continue  # Ya lo denuncia la otra prueba.

        if objetivo.suffix == ".md" and ancla not in _anclas(objetivo):
            rotas.append(destino)

    assert not rotas, "Anclas que no existen en %s: %s" % (
        path.relative_to(RAIZ), ", ".join(sorted(set(rotas))))


# Las dos portadas del repo se eligen entre sí, y no por un banner de arriba:
# una línea de idioma bajo el <div align="center">, como la que ya tienen. Sin
# esto, quien llega a la portada en un idioma que no es el suyo se queda sin
# puerta al otro, y no hay ninguna prueba que se entere.
@pytest.mark.parametrize("nombre, contraparte", [
    ("README.md", "README.es.md"),
    ("README.es.md", "README.md"),
])
def test_las_dos_portadas_se_enlazan_entre_si(nombre, contraparte):
    texto = (RAIZ / nombre).read_text(encoding="utf-8")

    assert "(%s)" % contraparte in texto, \
        "%s no enlaza a %s" % (nombre, contraparte)


# La documentación en inglés no es una copia parcial que se pueda ir comiendo:
# estos son los archivos que tienen que estar, y esta es la que comprueba que
# están los trece. Sin ella, un día se borra uno y la única pista es un enlace
# roto en una página que nadie visita.
ARCHIVOS_ENINGLES = (
    "README.es.md",
    "docs/en/installation.md",
    "docs/en/configuration.md",
    "docs/en/security.md",
    "docs/en/troubleshooting.md",
    "docs/en/wiki/README.md",
    "docs/en/wiki/getting-started.md",
    "docs/en/wiki/clients.md",
    "docs/en/wiki/policies.md",
    "docs/en/wiki/vpn-2fa.md",
    "docs/en/wiki/security.md",
    "docs/en/wiki/monitoring.md",
    "docs/en/wiki/maintenance.md",
)


@pytest.mark.parametrize("ruta", ARCHIVOS_ENINGLES)
def test_la_documentacion_inglesa_esta_completa(ruta):
    destino = RAIZ / ruta

    assert destino.exists(), "Falta %s" % ruta
    assert destino.read_text(encoding="utf-8").strip(), "%s está vacío" % ruta


# El ancla del emoji con el guion delante es el caso que se cuelga al recortar
# el resultado, así que se fija aquí a propósito: si alguien «limpia» la
# función para quitar espacios sobrantes, esta prueba lo dice antes de que lo
# digan de menos los enlaces del README.
@pytest.mark.parametrize("encabezado, esperado", [
    ("🚀 Instalación rápida", "-instalación-rápida"),
    ("👤 Clientes VPN", "-clientes-vpn"),
    ("Cómo se aplican", "cómo-se-aplican"),
    ("`max_intentos_login`", "max_intentos_login"),
    ("Puertos 1194/TCP y 443", "puertos-1194tcp-y-443"),
    ("Over", "over"),
    ("Cuotas 💰 por cliente", "cuotas-por-cliente"),
])
def test_el_ancla_se_calcula_como_lo_hace_github(encabezado, esperado):
    assert _ancla(encabezado) == esperado


# Los encabezados repetidos no repiten ancla, que es lo que los distingue de un
# enlace roto cuando dos apartados se llaman igual.
def test_un_encabezado_repetido_no_repite_ancla(tmp_path):
    pagina = tmp_path / "pagina.md"
    pagina.write_text("# Over\n\n## Over\n\n## Over\n", encoding="utf-8")

    assert _anclas(pagina) == {"over", "over-1", "over-2"}