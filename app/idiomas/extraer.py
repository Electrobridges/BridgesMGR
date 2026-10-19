"""
Saca del código todos los textos marcados para traducir y los compara con el
catálogo inglés.

    python -m app.idiomas.extraer          # resumen: qué falta y qué sobra
    python -m app.idiomas.extraer --faltan # solo los que faltan, como JSON
                                           # listo para pegar en en.json

Lo usa también tests/test_idiomas.py: lo que este script no encuentra, la
prueba tampoco lo vigila. Por eso las reglas de app/idiomas/__init__.py
(solo literales, nada de f-strings) no son de estilo.

Python se lee con ast, no con expresiones regulares: así no se confunde un
t( dentro de un comentario o de un docstring con una llamada de verdad.
"""

import ast
import json
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
APP = os.path.join(RAIZ, "app")
PLANTILLAS = os.path.join(APP, "templates")
CATALOGO_EN = os.path.join(APP, "idiomas", "en.json")

FUNCIONES = {"t", "th", "N_", "MensajeError"}
PLURALES = {"tn"}

# Un literal entre comillas simples o dobles, con escapes
_LIT = r"""(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"""
_RE_T = re.compile(r"(?<![\w.])(t|th|N_)\(\s*" + _LIT)
_RE_TN = re.compile(r"(?<![\w.])tn\(\s*" + _LIT + r"\s*,\s*" + _LIT)
_RE_MARCADOR = re.compile(r"%\((\w+)\)s")


def _literal_jinja(a, b):
    """El contenido de un literal de plantilla, con \\' \\" y \\\\ resueltos"""
    crudo = a if a is not None else b
    return re.sub(r"\\(.)", r"\1", crudo)


def _archivos(base, extension):
    for carpeta, subcarpetas, archivos in os.walk(base):
        subcarpetas[:] = [d for d in subcarpetas if d != "__pycache__"]
        for nombre in sorted(archivos):
            if nombre.endswith(extension):
                yield os.path.join(carpeta, nombre)


def _relativa(ruta):
    return os.path.relpath(ruta, RAIZ).replace(os.sep, "/")


def de_python(ruta):
    """(textos, plurales, problemas) de un archivo .py"""
    textos, plurales, problemas = {}, {}, []
    with open(ruta, encoding="utf-8") as f:
        arbol = ast.parse(f.read(), ruta)
    for nodo in ast.walk(arbol):
        if not (isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name)):
            continue
        nombre = nodo.func.id
        sitio = "%s:%d" % (_relativa(ruta), nodo.lineno)
        if nombre in FUNCIONES:
            if not nodo.args:
                continue
            arg = nodo.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                textos.setdefault(arg.value, []).append(sitio)
            elif isinstance(arg, (ast.JoinedStr, ast.BinOp)) or nombre in ("N_", "MensajeError"):
                # f-string, "a" + b o "x %s" % y: el extractor no lo puede leer
                problemas.append("%s: %s() con un texto que no es un literal" % (sitio, nombre))
        elif nombre in PLURALES:
            if len(nodo.args) < 3:
                problemas.append("%s: tn() necesita singular, plural y n" % sitio)
                continue
            uno, varios = nodo.args[0], nodo.args[1]
            if all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in (uno, varios)):
                plurales.setdefault(uno.value, (varios.value, []))[1].append(sitio)
            else:
                problemas.append("%s: tn() con textos que no son literales" % sitio)
    return textos, plurales, problemas


def de_plantilla(ruta):
    textos, plurales = {}, {}
    with open(ruta, encoding="utf-8") as f:
        contenido = f.read()
    # Los comentarios de Jinja no cuentan
    contenido = re.sub(r"\{#.*?#\}", lambda m: "\n" * m.group(0).count("\n"), contenido, flags=re.S)
    for m in _RE_T.finditer(contenido):
        linea = contenido.count("\n", 0, m.start()) + 1
        textos.setdefault(_literal_jinja(m.group(2), m.group(3)), []).append(
            "%s:%d" % (_relativa(ruta), linea))
    for m in _RE_TN.finditer(contenido):
        linea = contenido.count("\n", 0, m.start()) + 1
        uno = _literal_jinja(m.group(1), m.group(2))
        varios = _literal_jinja(m.group(3), m.group(4))
        plurales.setdefault(uno, (varios, []))[1].append("%s:%d" % (_relativa(ruta), linea))
    return textos, plurales


def extraer():
    """{'textos': {es: [sitios]}, 'plurales': {singular: (plural, [sitios])}, 'problemas': [...]}"""
    textos, plurales, problemas = {}, {}, []
    for ruta in _archivos(APP, ".py"):
        tx, pl, pr = de_python(ruta)
        for k, v in tx.items():
            textos.setdefault(k, []).extend(v)
        for k, (p, v) in pl.items():
            plurales.setdefault(k, (p, []))[1].extend(v)
        problemas.extend(pr)
    for ruta in _archivos(PLANTILLAS, ".html"):
        tx, pl = de_plantilla(ruta)
        for k, v in tx.items():
            textos.setdefault(k, []).extend(v)
        for k, (p, v) in pl.items():
            plurales.setdefault(k, (p, []))[1].extend(v)
    return {"textos": textos, "plurales": plurales, "problemas": problemas}


def catalogo_en():
    with open(CATALOGO_EN, encoding="utf-8") as f:
        return json.load(f)


def marcadores(texto):
    return sorted(set(_RE_MARCADOR.findall(texto)))


def comparar(extraido=None, catalogo=None):
    """Qué falta en el catálogo, qué sobra y qué traducciones no casan"""
    extraido = extraido or extraer()
    catalogo = catalogo or catalogo_en()
    cat_t, cat_p = catalogo.get("textos", {}), catalogo.get("plurales", {})

    faltan = {k: v for k, v in extraido["textos"].items() if not cat_t.get(k)}
    faltan_pl = {k: v for k, v in extraido["plurales"].items()
                 if not (isinstance(cat_p.get(k), list) and len(cat_p[k]) == 2 and all(cat_p[k]))}
    sobran = sorted(set(cat_t) - set(extraido["textos"]))
    sobran_pl = sorted(set(cat_p) - set(extraido["plurales"]))

    descuadres = []
    for es, en in cat_t.items():
        if en and marcadores(es) != marcadores(en):
            descuadres.append((es, en))
    for es, formas in cat_p.items():
        if es not in extraido["plurales"] or not isinstance(formas, list):
            continue
        plural_es = extraido["plurales"][es][0]
        esperados = set(marcadores(es)) | set(marcadores(plural_es))
        for forma in formas:
            # %(n)s puede ir en una forma y no en la otra ("one day" / "%(n)s days")
            if forma and (set(marcadores(forma)) - {"n"}) != (esperados - {"n"}):
                descuadres.append((es, forma))
    return {"faltan": faltan, "faltan_plurales": faltan_pl, "sobran": sobran,
            "sobran_plurales": sobran_pl, "descuadres": descuadres,
            "problemas": extraido["problemas"]}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    r = comparar()
    if "--faltan" in argv:
        json.dump({"textos": {k: "" for k in sorted(r["faltan"])},
                   "plurales": {k: ["", ""] for k in sorted(r["faltan_plurales"])}},
                  sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    for clave, titulo in (("problemas", "Llamadas que el extractor no puede leer"),
                          ("faltan", "Sin traducir en en.json"),
                          ("faltan_plurales", "Plurales sin traducir en en.json"),
                          ("sobran", "En en.json pero ya no en el código"),
                          ("sobran_plurales", "Plurales en en.json que ya no se usan"),
                          ("descuadres", "Traducciones con marcadores %(...)s distintos")):
        elementos = r[clave]
        print("%s: %d" % (titulo, len(elementos)))
        for e in (sorted(elementos) if isinstance(elementos, dict) else elementos)[:50]:
            sitios = elementos[e] if isinstance(elementos, dict) else None
            if isinstance(sitios, tuple):
                sitios = sitios[1]
            print("  ", e if not sitios else "%s  (%s)" % (e, sitios[0]))
    pendiente = any(r[k] for k in ("problemas", "faltan", "faltan_plurales", "descuadres"))
    return 1 if pendiente else 0


if __name__ == "__main__":
    sys.exit(main())
