"""
Idiomas de la interfaz: español (el de los textos fuente) e inglés.

Estas pruebas son la red para traducir el panel por partes. Vigilan cuatro
cosas, y cada una existe porque es como se rompe esto sin que nadie lo vea:

1. El catálogo: todo texto marcado en el código tiene su traducción, con los
   mismos %(huecos)s, y no sobra nada.
2. Las reglas de uso de t(): nada a nivel de módulo, nada no literal, nada en
   los módulos que manejan datos.
3. Las páginas ya traducidas no dejan frases en español cuando se piden en
   inglés.
4. Sin elegir nada, todo sigue en español, como siempre.
"""

import ast
import re
from pathlib import Path

import pytest
from starlette.requests import Request

from app import idiomas
from app.idiomas import extraer
from app.routers.idioma import COOKIE, del_navegador

from .conftest import PASSWORD_ADMIN, PASSWORD_SUPERVISOR

RAIZ = Path(__file__).resolve().parents[1]
APP = RAIZ / "app"
FUNCIONES_T = {"t", "th", "tn", "N_"}


@pytest.fixture(autouse=True)
def _idioma_limpio():
    """Ninguna prueba deja otro idioma por defecto a la siguiente"""
    yield
    idiomas.fijar_por_defecto("es")


# ------------------------------------------------------------ 1. el catálogo

@pytest.fixture(scope="module")
def comparacion():
    return extraer.comparar()


def test_el_extractor_lee_todas_las_llamadas(comparacion):
    """t(variable), t(f"...") o t("a" + b): el extractor no los ve y se quedan sin traducir"""
    assert comparacion["problemas"] == []


def test_ningun_texto_marcado_sin_traducir(comparacion):
    faltan = {k: v[0] for k, v in comparacion["faltan"].items()}
    faltan.update({k: v[1][0] for k, v in comparacion["faltan_plurales"].items()})
    assert faltan == {}, (
        "Textos marcados sin traducción en app/idiomas/en.json. "
        "'python -m app.idiomas.extraer --faltan' los lista listos para pegar."
    )


def test_el_catalogo_no_guarda_textos_que_ya_no_existen(comparacion):
    assert comparacion["sobran"] == []
    assert comparacion["sobran_plurales"] == []


def test_las_traducciones_respetan_los_huecos(comparacion):
    """Un %(cn)s que se pierde o cambia de nombre revienta al formatear, en inglés y solo ahí"""
    assert comparacion["descuadres"] == []


def test_el_catalogo_es_coherente():
    datos = extraer.catalogo_en()
    assert set(datos) <= {"textos", "plurales"}
    for es, en in datos["textos"].items():
        assert isinstance(en, str) and en.strip(), es
    for es, formas in datos["plurales"].items():
        assert isinstance(formas, list) and len(formas) == 2 and all(formas), es


# --------------------------------------------------- 2. las reglas de uso

def _py():
    return sorted(p for p in APP.rglob("*.py") if "__pycache__" not in p.parts)


def _llamadas_t(nodo):
    for n in ast.walk(nodo):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in FUNCIONES_T - {"N_"}:
            yield n


def test_nada_se_traduce_al_importar():
    """
    MENSAJE = t("...") a nivel de módulo se evalúa una vez, al importar, en el
    idioma por defecto, y ya no cambia. Para textos fijos: N_() al definirlos y
    t() al enseñarlos.
    """
    malos = []
    for ruta in _py():
        arbol = ast.parse(ruta.read_text(encoding="utf-8"))
        funciones = [(f.lineno, f.end_lineno) for f in ast.walk(arbol)
                     if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        for llamada in _llamadas_t(arbol):
            if not any(a <= llamada.lineno <= b for a, b in funciones):
                malos.append("%s:%d" % (ruta.relative_to(RAIZ), llamada.lineno))
    assert malos == []


def test_nadie_usa_guion_bajo_para_traducir():
    """
    En este código `_` es la variable de descarte (`_, x = ...`). Una función
    que la use y además llame a _("texto") revienta con UnboundLocalError, y
    solo cuando pasa por esa línea.
    """
    malos = []
    for ruta in _py():
        for n in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_"
                    and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)):
                malos.append("%s:%d" % (ruta.relative_to(RAIZ), n.lineno))
    plantillas = sorted((APP / "templates").rglob("*.html"))
    for ruta in plantillas:
        if re.search(r"(?<![\w.])_\(\s*['\"]", ruta.read_text(encoding="utf-8")):
            malos.append(str(ruta.relative_to(RAIZ)))
    assert malos == []


# Módulos cuyos textos son DATOS: se guardan en la base, se comparan con
# expresiones regulares o cruzan al helper y a los scripts de OpenVPN. Si se
# traducen, algo deja de casar sin dar ningún error.
SIN_TRADUCCION = (
    "app/db.py",
    "app/core/eventos_vpn.py",
)


@pytest.mark.parametrize("modulo", SIN_TRADUCCION)
def test_los_modulos_de_datos_no_traducen(modulo):
    """
    Pueden lanzar MensajeError, que guarda el texto sin traducir y se traduce
    donde se enseña; lo que no pueden es traducir ellos.
    """
    arbol = ast.parse((RAIZ / modulo).read_text(encoding="utf-8"))
    assert list(_llamadas_t(arbol)) == []
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.ImportFrom) and nodo.module and nodo.module.endswith("idiomas"):
            assert {a.name for a in nodo.names} <= {"MensajeError", "N_"}, modulo


def test_mensaje_error_guarda_el_espanol_y_traduce_al_ensenarlo():
    from app import db
    with idiomas.usar("en"):
        try:
            db.cambiar_password(":memory:", "ana", "corta")
        except ValueError as e:
            error = e
    # str(): lo que va a la auditoría, siempre en español
    assert str(error) == "La contraseña debe tener al menos 12 caracteres"
    with idiomas.usar("en"):
        assert idiomas.mensaje(error) == "The password must be at least 12 characters long"
    assert idiomas.mensaje(RuntimeError("del helper")) == "del helper"


def test_lo_que_cruza_la_frontera_no_importa_idiomas():
    """El helper y los scripts de OpenVPN son stdlib pura y hablan en datos fijos"""
    for ruta in (RAIZ / "deploy").iterdir():
        if ruta.is_file() and ruta.suffix in ("", ".py"):
            assert "idiomas" not in ruta.read_text(encoding="utf-8", errors="replace"), ruta.name


def test_menu_js_no_lleva_textos_propios():
    """Un .js estático no sabe el idioma de la página: los rótulos vienen en data-*"""
    js = (APP / "static" / "menu.js").read_text(encoding="utf-8")
    codigo = re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)
    assert "dataset.abrir" in codigo and "dataset.cerrar" in codigo
    assert "Abrir menú" not in codigo and "Cerrar menú" not in codigo


# ------------------------------------------------- el núcleo de idiomas

def test_en_espanol_el_texto_sale_tal_cual():
    with idiomas.usar("es"):
        assert idiomas.t("Clientes VPN") == "Clientes VPN"
        assert idiomas.t("Texto que no está en ningún catálogo %(x)s", x=1) == \
            "Texto que no está en ningún catálogo 1"


def test_en_ingles_se_traduce_y_lo_que_falta_cae_al_espanol():
    with idiomas.usar("en"):
        assert idiomas.t("Clientes VPN") == "VPN clients"
        assert idiomas.t("Sin traducir aún") == "Sin traducir aún"


def test_plurales():
    singular = "Demasiados intentos fallidos. Prueba de nuevo en %(n)s minuto."
    plural = "Demasiados intentos fallidos. Prueba de nuevo en %(n)s minutos."
    with idiomas.usar("es"):
        assert idiomas.tn(singular, plural, 1).endswith("1 minuto.")
        assert idiomas.tn(singular, plural, 5).endswith("5 minutos.")
    with idiomas.usar("en"):
        assert idiomas.tn(singular, plural, 1).endswith("1 minute.")
        assert idiomas.tn(singular, plural, 5).endswith("5 minutes.")


def test_th_escapa_lo_que_se_intercala_y_no_el_texto():
    marcado = idiomas.th("Cliente <strong>%(cn)s</strong>", cn="<script>x</script>")
    assert "<strong>" in marcado
    assert "<script>" not in marcado and "&lt;script&gt;" in marcado


def test_usar_restaura_el_idioma_anterior():
    with idiomas.usar("en"):
        with idiomas.usar("es"):
            assert idiomas.actual() == "es"
        assert idiomas.actual() == "en"
    assert idiomas.actual() == "es"


def test_fuera_de_una_peticion_manda_el_de_la_instalacion():
    """El vigilante y la CLI no tienen navegador: usan servidor.idioma"""
    idiomas.fijar_por_defecto("en")
    assert idiomas.t("Clientes VPN") == "VPN clients"
    idiomas.fijar_por_defecto("xx")
    assert idiomas.actual() == "es"


@pytest.mark.parametrize("cabecera,esperado", [
    ("en-US,en;q=0.9", "en"),
    ("es-ES,es;q=0.9,en;q=0.8", "es"),
    ("fr-FR,fr;q=0.9,en;q=0.5", "en"),
    ("fr-FR,de;q=0.9", None),
    ("es;q=0.2,en;q=0.8", "en"),
    ("en;q=0", None),
    ("", None),
    ("basura;;;q=x", None),
])
def test_accept_language(cabecera, esperado):
    assert del_navegador(cabecera) == esperado


def test_config_rechaza_un_idioma_desconocido(tmp_path):
    from app.config import cargar_config
    ruta = tmp_path / "config.yaml"
    ruta.write_text("servidor:\n  idioma: fr\n", encoding="utf-8")
    with pytest.raises(ValueError, match="idioma"):
        cargar_config(str(ruta))


# ----------------------------------------------------- 4. por defecto, español

def test_sin_elegir_nada_la_entrada_sigue_en_espanol(cliente):
    r = cliente.get("/login")
    assert '<html lang="es">' in r.text
    assert "Contraseña" in r.text and "Entrar" in r.text


def test_el_navegador_en_ingles_recibe_ingles(cliente):
    r = cliente.get("/login", headers={"Accept-Language": "en-GB,en;q=0.9"})
    assert '<html lang="en">' in r.text and "Password" in r.text


def test_la_cookie_manda_sobre_el_navegador(cliente):
    cliente.cookies.set(COOKIE, "es")
    r = cliente.get("/login", headers={"Accept-Language": "en"})
    assert '<html lang="es">' in r.text


def test_un_idioma_no_se_filtra_a_la_peticion_siguiente(cliente):
    assert '<html lang="en">' in cliente.get("/login", headers={"Accept-Language": "en"}).text
    assert '<html lang="es">' in cliente.get("/login").text
    assert idiomas.actual() == "es"


# ----------------------------------------------------- la ruta de cambio

def test_cambiar_de_idioma_pone_la_cookie_y_vuelve(cliente):
    r = cliente.get("/idioma/en?volver=/clientes", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/clientes"
    assert "idioma=en" in r.headers["set-cookie"]
    assert "httponly" in r.headers["set-cookie"].lower()


@pytest.mark.parametrize("volver", [
    "//otra.web/x", "https://otra.web", "/\\otra.web", "javascript:alert(1)", "", "/a\r\nSet-Cookie: x=1",
])
def test_cambiar_de_idioma_no_redirige_fuera(cliente, volver):
    r = cliente.get("/idioma/en", params={"volver": volver}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_un_idioma_desconocido_no_toca_la_cookie(cliente):
    r = cliente.get("/idioma/xx?volver=/", follow_redirects=False)
    assert r.status_code == 303
    assert "set-cookie" not in r.headers


def test_el_selector_aparece_en_la_entrada_y_en_la_barra(cliente, usuarios):
    assert 'href="/idioma/en?volver=' in cliente.get("/login").text
    cliente.post("/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN})
    assert 'class="selector-idioma"' in cliente.get("/").text


# ------------------------------------- 3. las páginas traducidas, en inglés

# Rasgos de una frase en español que no aparecen en inglés: letras que el
# inglés no usa y palabras gramaticales muy frecuentes. Es una heurística, y
# está ajustada para no dar falsos positivos en lo que sí puede salir en una
# página en inglés (nombres de clientes, rutas, el nombre de la marca).
_RASGOS_ES = re.compile(
    r"[áéíóúñ¿¡]|\b(el|la|los|las|del|de|que|con|para|por|una|un|es|en|su|sin|al|y|o"
    # Vocabulario del propio panel, para los rótulos cortos sin artículos
    # ni tildes ("Crear cliente", "Guardar")
    r"|crear|guardar|borrar|eliminar|descargar|cliente|clientes|usuario|usuarios"
    r"|conectado|conectados|activo|activa|revocar|revocado|revocados|restaurar"
    r"|horario|desde|hasta|nombre|fecha|ver|volver|cambiar|quitar|cerrar|abrir"
    r"|buscar|filtrar|todo|todos|ninguno|ninguna|minutos|segundos|hoy|ayer)\b",
    re.I,
)


def restos_en_espanol(html):
    """Frases en español que quedan en una página que debería estar en inglés"""
    # Fuera lo que no se lee o no es texto de la interfaz
    html = re.sub(r"<(script|style)\b.*?</\1>", " ", html, flags=re.S | re.I)
    html = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    # El selector nombra cada idioma en su idioma, a propósito
    html = re.sub(r'<nav class="selector-idioma".*?</nav>', " ", html, flags=re.S)
    # Atributos que lee una persona (lector de pantalla, tooltip, ejemplo)
    atributos = re.findall(r'\b(?:title|aria-label|placeholder|alt|data-abrir|data-cerrar|'
                           r'hx-confirm)="([^"]*)"', html)
    texto = re.sub(r"<[^>]+>", "\n", html)
    trozos = [t.strip() for t in texto.split("\n") + atributos]
    return sorted({t for t in trozos if t and _RASGOS_ES.search(t)})


# Páginas ya traducidas, con qué parte se comprueba: "todo" o la barra
# superior (que es de base.html y se traduce antes que el contenido). Cada
# fase de la traducción añade las suyas aquí; al terminar, todas en "todo".
#
# "todo" significa que la página entera se lee en inglés: si queda una frase
# en español, la prueba lo dice. Por eso, desde la fase 1, la barra deja de
# ser una parte aparte: el panel, las conexiones y los logs ya van enteros.
PAGINAS = {
    "/login": ("anonimo", "todo"),
    "/": ("admin", "todo"),
    "/conexiones": ("admin", "todo"),
    "/logs": ("admin", "todo"),
}


def _parte(html, parte):
    if parte == "todo":
        return html
    m = re.search(r'<header class="barra">.*?</header>', html, re.S)
    assert m, "la página no tiene barra"
    dialogo = re.search(r'<dialog id="dialogo-confirmar".*?</dialog>', html, re.S)
    return m.group(0) + (dialogo.group(0) if dialogo else "")


@pytest.mark.parametrize("ruta", sorted(PAGINAS))
def test_pagina_en_ingles_sin_restos_en_espanol(cliente, usuarios, ruta):
    quien, parte = PAGINAS[ruta]
    if quien == "admin":
        cliente.post("/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN})
    cliente.cookies.set(COOKIE, "en")
    r = cliente.get(ruta)
    assert r.status_code == 200, r.text[:300]
    assert '<html lang="en">' in r.text
    assert restos_en_espanol(_parte(r.text, parte)) == []


# Los fragmentos que HTMX inserta en las páginas. No son páginas: no llevan
# <html lang>, así que no valen para la prueba de arriba, y sin ellos la
# mayor parte del texto de la tabla de conexiones y del visor de logs
# —encabezados, plurales, el hx-confirm de desconectar— no lo vigila nadie.
FRAGMENTOS = {
    "/conexiones/tabla": "admin",
    "/logs/contenido": "admin",
}


@pytest.fixture
def conexiones_simuladas(monkeypatch):
    """
    Una conexión de mentira, para que la tabla tenga filas.

    Sin ella la tabla sale vacía y el botón de desconectar no se pinta: el
    texto que más falta vigilar es justamente el que vive en las filas.
    """
    import app.routers.panel as mod

    def obtener(cfg):
        return ([{
            "user": "ana",
            "real_ip": "192.168.1.50",
            "virtual_ip": "10.8.0.6",
            "bytes_recv": 1024,
            "bytes_sent": 2048,
            "connected_since": "10:15",
            "connected_seconds": 3600,
        }], "management", [])

    monkeypatch.setattr(mod, "obtener_conexiones", obtener)


@pytest.mark.parametrize("ruta", sorted(FRAGMENTOS))
def test_fragmento_en_ingles_sin_restos_en_espanol(cliente, usuarios, ruta, conexiones_simuladas):
    cliente.post("/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN})
    cliente.cookies.set(COOKIE, "en")
    r = cliente.get(ruta)
    assert r.status_code == 200, r.text[:300]
    assert restos_en_espanol(r.text) == []


def test_la_tabla_de_conexiones_despide_en_ingles(cliente, usuarios, conexiones_simuladas):
    """La fila tiene que estar en inglés, y el botón con su confirmación"""
    cliente.post("/login", data={"usuario": "jefa", "password": PASSWORD_ADMIN})
    cliente.cookies.set(COOKIE, "en")
    html = cliente.get("/conexiones/tabla").text

    assert "Real IP" in html and "Connected for" in html
    assert "Disconnect ana?" in html
    assert restos_en_espanol(html) == []


def test_el_403_se_enseña_en_el_idioma_de_quien_lo_recibe(cliente, usuarios):
    """La página de error es de la fase 1, así que su mensaje va con ella"""
    cliente.post("/login", data={"usuario": "mirona", "password": PASSWORD_SUPERVISOR})
    cliente.cookies.set(COOKIE, "en")
    r = cliente.get("/seguridad")

    assert r.status_code == 403
    assert "Your role does not allow this action" in r.text
    assert "Tu rol no permite" not in r.text


def test_la_verificacion_en_dos_pasos_en_ingles(app):
    """Sin pasar por todo el alta del segundo factor: se pinta la plantilla"""
    pedido = Request({"type": "http", "method": "GET", "path": "/login/codigo",
                      "query_string": b"", "headers": [], "app": app})
    with idiomas.usar("en"):
        html = app.state.plantillas.get_template("login_totp.html").render(
            request=pedido, sesion=None, manda=False, usuario="ana", error=None)
    assert restos_en_espanol(html) == []
    assert "Open your authenticator app and enter the code for ana." in html


def test_la_heuristica_detecta_lo_que_tiene_que_detectar():
    """Si esto deja de fallar donde debe, la prueba de arriba no vigila nada"""
    assert restos_en_espanol("<p>Crear cliente</p>") == ["Crear cliente"]
    assert restos_en_espanol("<p>Guardar</p>") == ["Guardar"]
    assert restos_en_espanol("<p>Descargar el perfil</p>") == ["Descargar el perfil"]
    assert restos_en_espanol('<input placeholder="contraseña">') == ["contraseña"]
    assert restos_en_espanol("<p>Download the profile</p>") == []
