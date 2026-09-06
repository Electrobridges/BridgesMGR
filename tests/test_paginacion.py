"""
Paginación y filtros de la auditoría.

La tabla crece sin límite y el log de OpenVPN también, así que la vista no puede
depender de traerlo todo. Del lado del panel se filtra y se pagina en SQL; del
lado de la VPN, en memoria sobre lo que ya viene acotado por la cola del
archivo.

Lo que más se comprueba aquí es el saneado: 'pagina' y 'por_pagina' llegan por
la URL y cualquiera puede escribir lo que quiera.
"""

import pytest

from app import db
from app.routers.comun import TAMANOS_PAGINA, paginar


# --------------------------------------------------------------- el helper

def test_reparte_las_paginas():
    pg = paginar(total=120, pagina=1, por_pagina=50, base="/x?a=1")

    assert pg["paginas"] == 3
    assert (pg["desde"], pg["hasta"]) == (1, 50)
    assert pg["desplazamiento"] == 0


def test_la_ultima_pagina_no_miente_en_el_recuento():
    pg = paginar(total=120, pagina=3, por_pagina=50, base="/x")

    assert (pg["desde"], pg["hasta"]) == (101, 120)


def test_un_tamano_inventado_cae_al_primero():
    """Llega por la URL: no puede convertirse en un LIMIT arbitrario"""
    assert paginar(10, 1, 99999, "/x")["por_pagina"] == TAMANOS_PAGINA[0]
    assert paginar(10, 1, -1, "/x")["por_pagina"] == TAMANOS_PAGINA[0]


@pytest.mark.parametrize("pedida,esperada", [(0, 1), (-5, 1), (999, 3)])
def test_una_pagina_fuera_de_rango_se_pega_al_extremo(pedida, esperada):
    """
    Y no deja la tabla vacía sin explicación, que es lo que haría un OFFSET
    más allá del final.
    """
    assert paginar(total=120, pagina=pedida, por_pagina=50, base="/x")["pagina"] == esperada


def test_sin_registros_no_hay_paginas_negativas():
    pg = paginar(total=0, pagina=1, por_pagina=50, base="/x")

    assert pg["paginas"] == 1
    assert (pg["desde"], pg["hasta"]) == (0, 0)


# ----------------------------------------------------------- la base

@pytest.fixture
def historial(cfg, usuarios):
    """Un historial variado: acciones de certificados, sesiones y un fallo"""
    ruta = cfg.seguridad.db_path
    for i in range(60):
        db.registrar(ruta, usuario="danieladm", accion="crear_cliente",
                     objetivo="cliente%d" % i)
    db.registrar(ruta, usuario="danieladm", accion="login", objetivo="danieladm")
    db.registrar(ruta, usuario="otro", accion="login", objetivo="otro",
                 resultado="error")
    return ruta


def test_cuenta_y_lista_coinciden(historial):
    assert db.contar_auditoria(historial) == 62
    assert len(db.listar_auditoria(historial, limite=50)) == 50


def test_el_desplazamiento_no_repite_filas(historial):
    primera = db.listar_auditoria(historial, limite=50, desplazamiento=0)
    segunda = db.listar_auditoria(historial, limite=50, desplazamiento=50)

    assert len(segunda) == 12
    assert not ({f["id"] for f in primera} & {f["id"] for f in segunda})


def test_filtro_de_fallos(historial):
    assert db.contar_auditoria(historial, "fallos") == 1
    assert db.listar_auditoria(historial, filtro="fallos")[0]["resultado"] == "error"


@pytest.mark.parametrize("resultado", ["2fa_pendiente", "iniciada", "descartada"])
def test_los_estados_a_medias_heredados_no_cuentan_como_fallo(historial, resultado):
    """
    Las instalaciones que ya existen guardan estos valores en `resultado`, de
    cuando los pasos a medias se anotaban ahí. La auditoría no se reescribe,
    así que es el filtro el que tiene que dejarlos fuera: nunca fueron fallos.
    """
    db.registrar(historial, usuario="danieladm", accion="login",
                 objetivo="danieladm", resultado=resultado)

    assert db.contar_auditoria(historial, "fallos") == 1


def test_la_etiqueta_y_el_filtro_usan_el_mismo_criterio():
    """
    La plantilla pinta en rojo lo que dice db.es_fallo, no lo que no sea 'ok':
    si cada uno lo decidiera por su cuenta, una fila podría salir en rojo y no
    aparecer en la pestaña de fallos.
    """
    for heredado in db.RESULTADOS_NO_FALLO:
        assert not db.es_fallo(heredado)
    for malo in ("fallo", "error", "bloqueado", "2fa_fallo", "denegada"):
        assert db.es_fallo(malo)


def test_filtro_de_certificados(historial):
    assert db.contar_auditoria(historial, "certificados") == 60


def test_filtro_de_sesiones(historial):
    assert db.contar_auditoria(historial, "sesiones") == 2


def test_un_filtro_inventado_no_llega_a_la_consulta(historial):
    """
    Los filtros son fragmentos SQL fijos elegidos por clave. Uno desconocido
    tiene que caer en 'todo', no acercarse a la consulta.
    """
    assert db.contar_auditoria(historial, "'; DROP TABLE auditoria; --") == 62
    assert db.contar_auditoria(historial, None) == 62


# ----------------------------------------------------------- por la web

def test_la_pagina_ensena_los_controles(como_admin, historial):
    texto = como_admin.get("/admin/auditoria").text

    assert "Mostrando" in texto
    assert "Por página" in texto
    assert "Página 1 de 2" in texto


def test_moverse_de_pagina_conserva_el_filtro(como_admin, historial):
    texto = como_admin.get("/admin/auditoria?fuente=panel&filtro=certificados").text

    assert "filtro=certificados&amp;por_pagina=50&amp;pagina=2" in texto


def test_el_tamano_de_pagina_se_respeta(como_admin, historial):
    texto = como_admin.get("/admin/auditoria?por_pagina=200").text

    # 62 entradas caben en una sola página de 200
    assert "Mostrando" in texto
    assert "Página 1 de" not in texto


def test_una_pagina_disparatada_no_deja_la_tabla_en_blanco(como_admin, historial):
    texto = como_admin.get("/admin/auditoria?pagina=9999").text

    assert "Página 2 de 2" in texto
    assert "cliente0" in texto


def test_los_dos_lados_tienen_filtros(como_admin, historial):
    """
    La pestaña de VPN tenía filtros y la del panel no. Que una vista ofrezca
    algo que su gemela no es de las cosas que se notan al usarlo.
    """
    panel = como_admin.get("/admin/auditoria?fuente=panel").text
    vpn = como_admin.get("/admin/auditoria?fuente=vpn").text

    assert 'class="filtros"' in panel
    assert 'class="filtros"' in vpn
