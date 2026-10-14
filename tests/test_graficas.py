"""
Gráficas del panel: geometría en el servidor y su paso por la página.
"""

from datetime import date, datetime, timedelta, timezone

import pytest

from app import db, estadisticas
from app.core import eventos_vpn
from app.core import graficas as gr


@pytest.mark.parametrize("valor, entero, paso", [
    (50, True, 20), (3, True, 1), (14, True, 5), (0.7, False, 0.25),
    (4.9e9, False, 2e9), (0, True, 1),
])
def test_el_paso_es_redondo_y_cubre_el_maximo(valor, entero, paso):
    assert gr.paso_redondo(valor, entero=entero) == paso
    assert gr.paso_redondo(valor, entero=entero) * gr.MARCAS >= valor


def test_las_marcas_del_eje_son_numeros_redondos():
    g = gr.columnas(["a", "b"], [{"nombre": "n", "clase": "serie-1", "valores": [7, 50]}],
                    entero=True)
    assert [m["texto"] for m in g["marcas"]] == ["0", "20", "40", "60"]


def test_columnas_apiladas():
    g = gr.columnas(
        ["2026-10-13", "2026-10-14"],
        [{"nombre": "Bajada", "clase": "serie-1", "valores": [100, 0]},
         {"nombre": "Subida", "clase": "serie-2", "valores": [50, 30]}],
        nombres_x={"2026-10-13": "13/10", "2026-10-14": "14/10"},
    )
    primera, segunda = g["columnas"]
    assert [s["clase"] for s in primera["segmentos"]] == ["serie-1", "serie-2"]
    # Un día con solo una serie no deja un segmento vacío
    assert [s["clase"] for s in segunda["segmentos"]] == ["serie-2"]
    assert primera["tip"].splitlines() == ["13/10", "Bajada: 100", "Subida: 50", "Total: 150"]
    assert len(g["leyenda"]) == 2
    assert g["tabla"]["filas"][1] == ("14/10", ["0", "30"])


def test_una_sola_serie_no_lleva_leyenda():
    g = gr.columnas(["a"], [{"nombre": "Conexiones", "clase": "serie-1", "valores": [3]}])
    assert g["leyenda"] == []


def test_sin_datos_lo_dice():
    g = gr.columnas(["a", "b"], [{"nombre": "x", "clase": "serie-1", "valores": [0, 0]}])
    assert g["vacia"] is True


def test_el_ranking_escala_al_mayor():
    filas = gr.barras([("ana", 200), ("luis", 50)])
    assert [f["largo"] for f in filas] == [100.0, 25.0]


def test_el_panel_pinta_las_graficas(como_admin, cfg):
    ruta = cfg.seguridad.db_path
    hoy = date.today().isoformat()
    db.sumar_trafico(ruta, hoy, {"ana": (1_000_000, 9_000_000)})
    db.guardar_eventos_vpn(ruta, [{"ts": hoy + " 10:00:00", "tipo": eventos_vpn.CONEXION,
                                   "cn": "ana", "ip": "1.1.1.1", "puerto": "1", "detalle": None}])

    r = como_admin.get("/")

    assert r.status_code == 200
    assert r.text.count('class="grafica-svg"') == 3
    assert 'data-tip="' in r.text and "Total: 10.0 MB" in r.text
    assert "ana" in r.text.split("Quién más tráfico")[1]
    # Sin estilos en línea: la CSP del panel los bloquearía
    assert ' style="' not in r.text


def test_series_por_dia(cfg):
    ruta = cfg.seguridad.db_path
    db.init_db(ruta)
    db.guardar_eventos_vpn(ruta, [
        {"ts": "", "tipo": eventos_vpn.RECHAZO_CLAVE, "cn": "", "ip": "1.1.1.1",
         "puerto": "1", "detalle": None}] * 3)
    g = estadisticas.sucesos_diarios(ruta, eventos_vpn.FALLOS, "Rechazos")
    # Sin fecha en el log, cuenta el día en que se leyó
    assert g["tabla"]["filas"][-1][1] == ["3"]


@pytest.mark.parametrize("visto, horas, dia", [
    (datetime(2026, 10, 14, 23, 30, tzinfo=timezone.utc), 2, "2026-10-15"),
    (datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc), -5, "2026-10-14"),
])
def test_un_suceso_sin_fecha_cuenta_en_el_dia_local(
        cfg, monkeypatch, visto, horas, dia):
    # `visto` va en UTC y las columnas son días locales: cerca de medianoche
    # el día UTC es otro y el suceso caía en la columna equivocada
    ruta = cfg.seguridad.db_path
    db.init_db(ruta)
    monkeypatch.setattr(db, "_ahora", lambda: visto)
    db.guardar_eventos_vpn(ruta, [
        {"ts": "", "tipo": eventos_vpn.RECHAZO_CLAVE, "cn": "", "ip": "1.1.1.1",
         "puerto": "1", "detalle": None}])

    zona = timezone(timedelta(hours=horas))
    assert db.eventos_por_dia(ruta, eventos_vpn.FALLOS, "2026-10-01", zona) == {dia: 1}
