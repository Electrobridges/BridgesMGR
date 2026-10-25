"""
Las series que pintan las gráficas del panel, sacadas de la base.

Todo de lo que el panel ya guarda —el tráfico por día que suma el vigilante y
los sucesos del log—: ninguna gráfica pregunta al helper ni al management, así
que abrir el panel no cuesta más que antes.
"""

from datetime import date

from . import db, trafico
from .core import eventos_vpn
from .core import graficas as gr
from .idiomas import N_, t

DIAS = 30

# Los nombres de las series se enseñan (leyenda, tooltip y cabecera de la
# tabla): se marcan aquí y se traducen donde se usan.
SUBIDA = N_("Subida")
BAJADA = N_("Bajada")


def _rellenar(dias, valores, defecto=0):
    return [valores.get(d, defecto) for d in dias]


def trafico_diario(ruta, cn=None, dias=DIAS, hoy=None):
    """Subida y bajada por día, apiladas. De todos, o de un cliente."""
    etiquetas = gr.ultimos_dias(dias, hoy)
    datos = db.trafico_por_dia(ruta, etiquetas[0], cn)
    # 'recibido' es lo que el servidor recibe del cliente: su SUBIDA.
    return gr.columnas(
        etiquetas,
        [
            {"nombre": t(BAJADA), "clase": "serie-1",
             "valores": _rellenar(etiquetas, {d: e for d, (r, e) in datos.items()})},
            {"nombre": t(SUBIDA), "clase": "serie-2",
             "valores": _rellenar(etiquetas, {d: r for d, (r, e) in datos.items()})},
        ],
        formato=trafico.bytes_decimales,
        formato_eje=gr.bytes_compacto,
        nombres_x={d: gr.fecha_corta(d) for d in etiquetas},
    )


def sucesos_diarios(ruta, tipos, nombre, dias=DIAS, hoy=None):
    etiquetas = gr.ultimos_dias(dias, hoy)
    datos = db.eventos_por_dia(ruta, tipos, etiquetas[0])
    return gr.columnas(
        etiquetas,
        [{"nombre": nombre, "clase": "serie-1", "valores": _rellenar(etiquetas, datos)}],
        formato=lambda n: "%d" % n,
        formato_eje=lambda n: gr.compacto(n),
        nombres_x={d: gr.fecha_corta(d) for d in etiquetas},
        entero=True,
    )


def ranking_mes(ruta, limite=6, hoy=None):
    """Los clientes con más tráfico este mes, de mayor a menor."""
    mes = (hoy or date.today()).strftime("%Y-%m")
    filas = sorted(((cn, r + e) for cn, (r, e) in db.trafico_mes(ruta, mes).items()),
                   key=lambda f: f[1], reverse=True)[:limite]
    return gr.barras(filas, formato=trafico.bytes_decimales)


def panel(ruta, hoy=None):
    return {
        "trafico": trafico_diario(ruta, hoy=hoy),
        "conexiones": sucesos_diarios(ruta, {eventos_vpn.CONEXION}, t("Conexiones"), hoy=hoy),
        "rechazos": sucesos_diarios(ruta, eventos_vpn.FALLOS, t("Rechazos"), hoy=hoy),
        "ranking": ranking_mes(ruta, hoy=hoy),
    }
