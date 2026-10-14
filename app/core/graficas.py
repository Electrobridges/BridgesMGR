"""
Geometría de las gráficas del panel, en SVG generado en el servidor.

Sin librerías de gráficas ni JavaScript de un CDN: la CSP del panel es
script-src 'self' y no se afloja por una gráfica. Aquí solo se calculan
posiciones —rectángulos, trazos, marcas de eje— y la plantilla
partials/grafica.html las pinta. El color va por clase CSS (serie-1,
serie-2), nunca como atributo, para que lo decida estilo.css.

Convenciones de la guía de visualización que se siguen:

- Columnas de 24 px como mucho, con la punta redondeada (4 px) y la base
  recta sobre una sola línea de base.
- En las apiladas, 2 px de separación entre segmentos, del color del fondo.
- Ejes y rejilla discretos; marcas del eje Y en números redondos y compactos.
- Cada columna lleva un área de pasada más grande que la marca, con el
  texto del tooltip: así se lee el valor sin apuntar a un segmento de 3 px.

Solo stdlib y sin E/S: se prueba sin levantar la web.
"""

import math
from datetime import date, timedelta

ANCHO = 640
ALTO = 190
MARGEN_IZQ = 48
MARGEN_DER = 8
MARGEN_SUP = 10
MARGEN_INF = 24
COLUMNA_MAX = 24
RADIO = 4
SEPARACION = 2


MARCAS = 3


def paso_redondo(valor, marcas=MARCAS, entero=False):
    """
    El paso redondo (1, 2, 2.5, 5 × 10^n) para que 'marcas' pasos cubran 'valor'.

    Se redondea el PASO y no el máximo: con un máximo redondo partido en tres
    salían marcas como 16.7 o 33.3, que no se leen de un vistazo. 'entero' es
    para recuentos, donde un paso de 0.5 conexiones no significa nada.
    """
    if valor <= 0:
        return 1
    bruto = valor / marcas
    potencia = 10 ** math.floor(math.log10(bruto))
    for m in (1, 2, 2.5, 5, 10):
        paso = m * potencia
        if entero and (paso < 1 or paso != int(paso)):
            continue
        if paso * marcas >= valor:
            return paso
    return 10 * potencia


def compacto(n, unidades=("", "K", "M", "G", "T"), base=1000):
    """1234 -> '1.2K'. Para bytes, unidades=('B','KB',...)."""
    for unidad in unidades:
        if abs(n) < base or unidad == unidades[-1]:
            if n == int(n) or abs(n) >= 100:
                return "%d %s" % (round(n), unidad) if unidad in ("B", "KB", "MB", "GB", "TB") \
                    else "%d%s" % (round(n), unidad)
            texto = ("%.1f" % n).rstrip("0").rstrip(".")
            return ("%s %s" % (texto, unidad)) if unidad in ("B", "KB", "MB", "GB", "TB") \
                else "%s%s" % (texto, unidad)
        n /= base
    return str(n)


BYTES = ("B", "KB", "MB", "GB", "TB")


def bytes_compacto(n):
    return compacto(n, BYTES)


def ultimos_dias(n, hoy=None):
    hoy = hoy or date.today()
    return [(hoy - timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]


def _columna(x, y_base, ancho, alto, redondear_arriba):
    """Trazo de una columna: base recta, punta redondeada si toca."""
    if alto <= 0:
        return ""
    r = min(RADIO, ancho / 2, alto) if redondear_arriba else 0
    arriba = y_base - alto
    if not r:
        return "M%.1f %.1fh%.1fv%.1fh%.1fZ" % (x, y_base, ancho, -alto, -ancho)
    return ("M%.1f %.1f" % (x, y_base)
            + "V%.1f" % (arriba + r)
            + "Q%.1f %.1f %.1f %.1f" % (x, arriba, x + r, arriba)
            + "H%.1f" % (x + ancho - r)
            + "Q%.1f %.1f %.1f %.1f" % (x + ancho, arriba, x + ancho, arriba + r)
            + "V%.1f" % y_base + "Z")


def columnas(etiquetas, series, formato=compacto, formato_eje=None, cada_etiqueta=7,
             nombres_x=None, entero=False):
    """
    Columnas, apiladas si hay más de una serie.

    'etiquetas' son las claves del eje X (p. ej. fechas ISO); 'series' es una
    lista de {'nombre', 'clase', 'valores'} con un valor por etiqueta, de la
    base hacia arriba. 'formato' convierte un valor en texto para el tooltip
    y 'formato_eje' para las marcas del eje (por defecto, el mismo).

    Devuelve un diccionario listo para partials/grafica.html.
    """
    formato_eje = formato_eje or formato
    nombres_x = nombres_x or {}
    n = max(1, len(etiquetas))
    totales = [sum(s["valores"][i] for s in series) for i in range(len(etiquetas))]
    paso = paso_redondo(max(totales) if totales else 0, entero=entero)
    maximo = paso * MARCAS

    area_ancho = ANCHO - MARGEN_IZQ - MARGEN_DER
    area_alto = ALTO - MARGEN_SUP - MARGEN_INF
    banda = area_ancho / n
    ancho_col = min(COLUMNA_MAX, banda * 0.62)
    y_base = MARGEN_SUP + area_alto

    columnas_svg = []
    for i, etiqueta in enumerate(etiquetas):
        x = MARGEN_IZQ + banda * i + (banda - ancho_col) / 2
        segmentos = []
        acumulado = 0.0
        visibles = [j for j, s in enumerate(series) if s["valores"][i] > 0]
        for j, s in enumerate(series):
            valor = s["valores"][i]
            if valor <= 0:
                continue
            alto = area_alto * valor / maximo
            # La separación entre segmentos se come el segmento de arriba, no
            # el total: la altura de la pila sigue siendo la del dato.
            hueco = SEPARACION if acumulado > 0 else 0
            base = y_base - acumulado
            dibujo = max(0.0, alto - hueco)
            es_ultimo = j == visibles[-1]
            segmentos.append({
                "clase": s["clase"],
                "d": _columna(x, base - hueco, ancho_col, dibujo, es_ultimo),
            })
            acumulado += alto

        nombre = nombres_x.get(etiqueta, etiqueta)
        lineas = [nombre] + ["%s: %s" % (s["nombre"], formato(s["valores"][i])) for s in series]
        if len(series) > 1:
            lineas.append("Total: %s" % formato(totales[i]))
        columnas_svg.append({
            "segmentos": segmentos,
            "zona": {"x": MARGEN_IZQ + banda * i, "ancho": banda,
                     "y": MARGEN_SUP, "alto": area_alto},
            "tip": "\n".join(lineas),
        })

    marcas = []
    for k in range(MARCAS + 1):
        marcas.append({"y": y_base - area_alto * k / MARCAS, "texto": formato_eje(paso * k)})

    eje_x = []
    for i, etiqueta in enumerate(etiquetas):
        # La última siempre, y hacia atrás cada 'cada_etiqueta': así el día de
        # hoy tiene nombre aunque el total no sea múltiplo del paso.
        if (n - 1 - i) % cada_etiqueta == 0:
            eje_x.append({"x": MARGEN_IZQ + banda * i + banda / 2,
                          "texto": nombres_x.get(etiqueta, etiqueta)})

    return {
        "ancho": ANCHO, "alto": ALTO, "y_base": y_base,
        "x0": MARGEN_IZQ, "x1": ANCHO - MARGEN_DER,
        "columnas": columnas_svg, "marcas": marcas, "eje_x": eje_x,
        "leyenda": [{"nombre": s["nombre"], "clase": s["clase"]} for s in series]
                   if len(series) > 1 else [],
        "vacia": not any(totales),
        "tabla": {
            "cabecera": [s["nombre"] for s in series],
            "filas": [(nombres_x.get(e, e), [formato(s["valores"][i]) for s in series])
                      for i, e in enumerate(etiquetas)],
        },
    }


def barras(filas, formato=compacto, clase="serie-1"):
    """
    Barras horizontales para un ranking: [(nombre, valor)] de mayor a menor.

    Cada barra es un SVG propio de 100 de ancho: el largo va en el atributo
    'width', que la CSP sí deja (un 'style="width: …"' en línea, no).
    """
    maximo = max((v for _, v in filas), default=0) or 1
    return [{"nombre": nombre, "valor": formato(valor), "clase": clase,
             "largo": round(max(0.8, 100.0 * valor / maximo), 2)} for nombre, valor in filas]


def fecha_corta(iso):
    """'2026-10-14' -> '14/10'"""
    return "%s/%s" % (iso[8:10], iso[5:7])
