"""
Idioma de la interfaz: español (el de siempre, y el de los textos fuente) e
inglés.

Cómo funciona, en corto:

- Los textos se escriben en español en el código y en las plantillas, tal cual,
  envueltos en t(), th() o tn(). Ese texto español ES la clave del catálogo.
- En español se devuelven sin tocar. En inglés se buscan en en.json; si falta
  alguno se devuelve el español, y tests/test_idiomas.py lo detecta antes de
  que llegue a nadie.
- El idioma de cada petición vive en una ContextVar que pone el middleware de
  main.py. Los endpoints síncronos de FastAPI corren en un hilo, pero Starlette
  copia el contexto al lanzarlos, así que lo ven. Lo que corre fuera de una
  petición —el vigilante, la CLI— usa el idioma por defecto de la instalación.

Por qué t() y no _(), que es lo habitual: en este código `_` ya se usa como
variable de descarte (`_, x = ...`, `for _ in ...`). En una función que haga
eso, `_` pasa a ser local en toda la función y una llamada a _("texto")
revienta con UnboundLocalError, solo en esa función y solo cuando se ejecuta.

Tres reglas que vigila la prueba:

1. Solo literales: t("Texto %(n)s", n=x), nunca t(variable) ni t(f"..."). Lo
   que no es literal no lo encuentra el extractor y se queda sin traducir.
   La excepción son los textos marcados con N_() donde se definen, que se
   traducen después con t(variable).
2. Nunca a nivel de módulo: una constante MENSAJE = t("...") se evalúa al
   importar, una sola vez y en el idioma por defecto. Para listas de textos
   fijos, N_() donde se definen y t() donde se enseñan.
3. Nada que sea un dato: lo que se guarda en la base, lo que se compara con
   una expresión regular, lo que cruza al helper o a los scripts de OpenVPN.
   Eso se queda en español siempre y, si hay que enseñarlo, se traduce al
   enseñarlo.

Solo stdlib y markupsafe (que ya trae Jinja2).
"""

import contextlib
import contextvars
import json
import os

from markupsafe import Markup, escape

IDIOMAS = ("es", "en")
NOMBRES = {"es": "Español", "en": "English"}
FUENTE = "es"

_DIR = os.path.dirname(os.path.abspath(__file__))
_actual = contextvars.ContextVar("idioma", default=None)
_por_defecto = FUENTE
_catalogos = {}


def normalizar(codigo):
    """'en-US' -> 'en'; lo que no se conoce, None"""
    if not codigo:
        return None
    base = str(codigo).strip().lower().replace("_", "-").split("-")[0]
    return base if base in IDIOMAS else None


def fijar_por_defecto(codigo):
    """El de la instalación (servidor.idioma en config.yaml). Lo llama main.py."""
    global _por_defecto
    _por_defecto = normalizar(codigo) or FUENTE


def por_defecto():
    return _por_defecto


def actual():
    return _actual.get() or _por_defecto


def fijar(codigo):
    """Fija el idioma del contexto actual. Devuelve el token para restaurarlo."""
    return _actual.set(normalizar(codigo) or _por_defecto)


def restaurar(token):
    _actual.reset(token)


@contextlib.contextmanager
def usar(codigo):
    """Para el código que corre fuera de una petición y quiere otro idioma."""
    token = fijar(codigo)
    try:
        yield
    finally:
        restaurar(token)


def catalogo(codigo):
    """{'textos': {es: trad}, 'plurales': {singular_es: [singular, plural]}}"""
    if codigo == FUENTE:
        return {"textos": {}, "plurales": {}}
    if codigo not in _catalogos:
        ruta = os.path.join(_DIR, "%s.json" % codigo)
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
        _catalogos[codigo] = {
            "textos": datos.get("textos", {}),
            "plurales": datos.get("plurales", {}),
        }
    return _catalogos[codigo]


def _formatear(texto, valores):
    return texto % valores if valores else texto


def t(texto, **valores):
    """Texto plano traducido. Los %(nombre)s se rellenan con 'valores'."""
    traducido = catalogo(actual())["textos"].get(texto) or texto
    return _formatear(traducido, valores)


def tn(singular, plural, n, **valores):
    """
    Singular o plural según n, que además se puede usar como %(n)s.

    Español e inglés comparten regla (uno / el resto), así que basta con dos
    formas. La clave en el catálogo es el singular español.
    """
    valores.setdefault("n", n)
    formas = catalogo(actual())["plurales"].get(singular)
    if formas:
        texto = formas[0] if n == 1 else formas[1]
    else:
        texto = singular if n == 1 else plural
    return _formatear(texto, valores)


def th(texto, **valores):
    """
    Como t(), para un literal que lleva HTML en línea (<strong>, <code>, <a>).

    El literal y su traducción son de confianza: los escribimos nosotros. Lo
    que no lo es son los valores que se intercalan —un CN, un nombre de
    usuario—, así que se escapan antes de entrar. Devuelve Markup para que
    Jinja no vuelva a escapar el HTML del propio texto.
    """
    traducido = catalogo(actual())["textos"].get(texto) or texto
    seguros = {k: escape(v) for k, v in valores.items()}
    return Markup(_formatear(traducido, seguros))


def N_(texto):
    """
    Marca un texto para traducir más tarde, sin traducirlo ahora.

    Para las listas fijas que se definen al importar el módulo (nombres de los
    días, categorías de aviso, títulos de la auditoría): N_() donde se definen,
    t(variable) donde se enseñan.
    """
    return texto



class MensajeError(ValueError):
    """
    Un error que acaba en pantalla, lanzado desde un módulo que no debe
    traducir (db.py, la validación del núcleo).

    Guarda el texto fuente y sus valores sin traducir, así que:
    - str(e) es el mensaje en español, ya rellenado: es lo que va a la
      auditoría y a los logs, que son datos y no cambian de idioma;
    - mensaje(e) es el mismo mensaje en el idioma de quien lo va a leer.

    Es un ValueError: los `except ValueError` de siempre lo siguen cogiendo.
    """

    def __init__(self, texto, **valores):
        super().__init__(_formatear(texto, valores))
        self.texto = texto
        self.valores = valores


def mensaje(error):
    """El texto de un error para enseñarlo. Los que no son MensajeError, tal cual."""
    if isinstance(error, MensajeError):
        return t(error.texto, **error.valores)
    return str(error)


# Los roles se guardan en la base con su nombre español y así se quedan: son
# datos, y hay índices y comprobaciones que dependen de ellos. Lo que se
# traduce es solo cómo se enseñan.
_ROLES = {
    "superusuario": N_("superusuario"),
    "admin": N_("admin"),
    "supervisor": N_("supervisor"),
}


def nombre_rol(rol):
    """El nombre de un rol para enseñarlo. El valor guardado no cambia nunca."""
    return t(_ROLES[rol]) if rol in _ROLES else rol
