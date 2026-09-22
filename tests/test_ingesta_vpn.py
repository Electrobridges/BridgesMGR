"""
Ingesta del log de OpenVPN a la tabla `eventos_vpn`.

Lo que se prueba aquí no es el parseo —eso está en test_eventos_vpn.py— sino
las dos cosas que hacen que guardar sirva de algo: que **no se repita** lo ya
leído, porque lo único que lo impide es el cursor, y que **no se pierda** lo
que se quedó en el archivo cuando logrotate lo vació, porque con
'copytruncate' ese tramo solo existe en la copia que dejó la rotación.

La tercera es que un hueco se cuente. Un registro de accesos con una semana en
blanco que nadie anunció es peor que no tener registro: se lee como una semana
tranquila.
"""

import gzip
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import db, eventos
from app.core import eventos_vpn as ev

CONEXION = ("2026-07-30 10:00:01 192.168.1.50:49711 [daniel] Peer Connection "
            "Initiated with [AF_INET]192.168.1.50:49711\n")
DESCONEXION = ("2026-07-30 12:33:00 daniel/192.168.1.50:49711 SIGTERM[soft,"
               "remote-exit] received, client-instance exiting\n")
RECHAZO = ("2026-07-30 10:05:00 192.168.1.77:51001 VERIFY ERROR: depth=0, "
           "error=certificate revoked: CN=antiguo-becario\n")
ARRANQUE = "2026-07-30 09:00:00 Initialization Sequence Completed\n"


@pytest.fixture
def base(cfg):
    """La base creada, sin levantar la app: la ingesta no necesita web"""
    db.init_db(cfg.seguridad.db_path)
    return cfg.seguridad.db_path


def _escribir(cfg, texto, modo="w"):
    with open(cfg.openvpn.log_path, modo, encoding="utf-8") as f:
        f.write(texto)


# ------------------------------------------------------------ lo básico

def test_los_sucesos_del_log_acaban_en_la_base(cfg, base):
    _escribir(cfg, CONEXION + RECHAZO)

    assert eventos.ingerir(cfg) == 2

    guardados = db.listar_eventos_vpn(base)
    assert [e["tipo"] for e in guardados] == [ev.RECHAZO_REVOCADO, ev.CONEXION]
    assert guardados[1]["cn"] == "daniel"
    assert guardados[1]["ts"] == "2026-07-30 10:00:01"


def test_el_mas_reciente_sale_primero(cfg, base):
    """
    Se guardan en el orden del log y se leen por 'id DESC'. Si se insertaran
    como los devuelve parse_eventos() —el más reciente primero— la tabla
    quedaría del revés y la pestaña enseñaría lo más viejo arriba.
    """
    _escribir(cfg, ARRANQUE + CONEXION + DESCONEXION)
    eventos.ingerir(cfg)

    assert [e["tipo"] for e in db.listar_eventos_vpn(base)] == [
        ev.DESCONEXION, ev.CONEXION, ev.ARRANQUE,
    ]


def test_el_panel_apunta_cuando_lo_leyo_aunque_el_log_no_feche(cfg, base):
    """
    'ts' es lo que escribió OpenVPN y puede venir vacío; 'visto' lo pone el
    panel y es lo que después permite purgar por antigüedad. Sin la segunda
    fecha, un log sin marcas de tiempo daría filas que no se pueden purgar.
    """
    _escribir(cfg, "127.0.0.1:57176 [alfa2] Peer Connection Initiated with "
                   "[AF_INET]127.0.0.1:57176\n")
    eventos.ingerir(cfg)

    guardado = db.listar_eventos_vpn(base)[0]
    assert guardado["ts"] == ""
    assert guardado["visto"]


def test_fallo_se_deriva_del_tipo_y_no_se_guarda(cfg, base):
    """
    Guardarlo dejaría filas viejas contestando distinto que el código el día
    que se añada un tipo de rechazo nuevo.
    """
    _escribir(cfg, CONEXION + RECHAZO)
    eventos.ingerir(cfg)

    por_tipo = {e["tipo"]: e for e in db.listar_eventos_vpn(base)}
    assert por_tipo[ev.RECHAZO_REVOCADO]["fallo"] is True
    assert por_tipo[ev.CONEXION]["fallo"] is False


# --------------------------------------------------------- el cursor

def test_pasar_dos_veces_no_duplica_nada(cfg, base):
    _escribir(cfg, CONEXION + RECHAZO)
    eventos.ingerir(cfg)

    assert eventos.ingerir(cfg) == 0
    assert db.contar_eventos_vpn(base) == 2


def test_la_vuelta_siguiente_solo_se_lleva_lo_nuevo(cfg, base):
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)

    _escribir(cfg, DESCONEXION, modo="a")

    assert eventos.ingerir(cfg) == 1
    assert db.contar_eventos_vpn(base) == 2


def test_el_historial_sobrevive_a_que_el_log_se_vacie(cfg, base):
    """
    El caso que motiva todo esto: logrotate vacía el log cada semana y antes se
    llevaba por delante lo que la pestaña podía enseñar.
    """
    _escribir(cfg, CONEXION + DESCONEXION)
    eventos.ingerir(cfg)

    _escribir(cfg, "")  # copytruncate: mismo archivo, tamaño cero
    eventos.ingerir(cfg)

    assert db.contar_eventos_vpn(base) == 2


def test_un_cursor_ilegible_no_deja_al_panel_sin_ingerir_para_siempre(cfg, base):
    db.guardar_ajuste(base, eventos.AJUSTE_CURSOR, "esto-no-es-un-numero")
    _escribir(cfg, CONEXION)

    assert eventos.ingerir(cfg) == 1


def test_la_primera_vuelta_se_pone_al_dia_de_un_log_ya_escrito(cfg, base, monkeypatch):
    """
    Un log de semanas no cabe en una sola lectura, y a un bloque por vuelta el
    panel tardaría una hora en enseñar lo que ya está en el archivo. El bloque
    se achica aquí en vez de escribir megas de log: lo que se prueba es que se
    repita, no cuánto cabe.
    """
    monkeypatch.setattr(ev, "BLOQUE_MAX", len(CONEXION) * 2)
    _escribir(cfg, CONEXION * 10)

    assert eventos.ingerir(cfg) == 10


def test_lo_que_no_entra_en_una_vuelta_se_lee_en_la_siguiente(cfg, base, monkeypatch):
    """
    El techo de pasadas existe para no dejar al hilo del vigilante leyendo un
    log gigante mientras lo demás espera. Lo que queda no se pierde: el cursor
    se queda donde llegó.
    """
    monkeypatch.setattr(ev, "BLOQUE_MAX", len(CONEXION))
    monkeypatch.setattr(eventos, "PASADAS_MAX", 2)
    _escribir(cfg, CONEXION * 5)

    assert eventos.ingerir(cfg) == 2
    assert eventos.ingerir(cfg) == 2
    assert eventos.ingerir(cfg) == 1
    assert db.contar_eventos_vpn(base) == 5


# ------------------------------------------------------ la rotación

def _rotar(cfg, nuevo=""):
    """
    Lo que hace logrotate con 'copytruncate': corre los '.N', copia el archivo
    vivo a '.1' y lo vacía sin cambiarle el inodo.

    Se imita en vez de llamar a logrotate porque lo que se prueba es la
    reacción del panel, y así la prueba corre en Windows y sin root.
    """
    ruta = cfg.openvpn.log_path

    if os.path.exists(ruta + ".1"):
        os.replace(ruta + ".1", ruta + ".2")

    with open(ruta, "r", encoding="utf-8") as f:
        copia = f.read()
    with open(ruta + ".1", "w", encoding="utf-8") as f:
        f.write(copia)

    _escribir(cfg, nuevo)


def test_lo_escrito_justo_antes_de_rotar_se_rescata_de_la_copia(cfg, base):
    """
    Entre la última vuelta y el vaciado hay un tramo que solo queda en '.1'.
    Sin ir a buscarlo se perdería una semana entera cada vez que el panel
    estuviera parado en el momento de rotar.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)

    # Esto se escribe después de la última lectura y antes de la rotación
    _escribir(cfg, DESCONEXION, modo="a")
    _rotar(cfg, nuevo=ARRANQUE)

    assert eventos.ingerir(cfg) == 2
    assert [e["tipo"] for e in db.listar_eventos_vpn(base)] == [
        ev.ARRANQUE, ev.DESCONEXION, ev.CONEXION,
    ]


def test_el_rescate_no_reingiere_lo_que_ya_estaba(cfg, base):
    """La copia contiene TODO el archivo, también el tramo ya leído"""
    _escribir(cfg, CONEXION + DESCONEXION)
    eventos.ingerir(cfg)

    _rotar(cfg)
    eventos.ingerir(cfg)

    assert db.contar_eventos_vpn(base) == 2


def test_si_no_hay_copia_el_hueco_se_cuenta(cfg, base):
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)

    _escribir(cfg, DESCONEXION, modo="a")
    _escribir(cfg, "")  # vaciado sin copia: ese tramo no está en ninguna parte

    eventos.ingerir(cfg)

    assert any("Faltan sucesos" in a for a in eventos.avisos(cfg))


def test_dos_rotaciones_sin_mirar_no_se_leen_como_una(cfg, base):
    """
    Con el panel parado dos semanas, '.1' es la copia de la semana siguiente y
    no la de lo que estábamos leyendo: leerla por nuestro desplazamiento daría
    texto de la mitad de otro archivo. Vale más un hueco declarado.
    """
    _escribir(cfg, CONEXION * 20)
    eventos.ingerir(cfg)

    _rotar(cfg, nuevo=DESCONEXION)
    _rotar(cfg, nuevo=ARRANQUE)

    antes = db.contar_eventos_vpn(base)
    eventos.ingerir(cfg)

    assert any("más de una vez" in a for a in eventos.avisos(cfg))
    # Lo del archivo vivo sí entra: lo que se declara perdido es el tramo viejo
    assert db.contar_eventos_vpn(base) == antes + 1


def test_el_hueco_no_se_borra_en_la_vuelta_siguiente(cfg, base):
    """
    El agujero que anuncia tampoco se cierra. Quien audite esto dentro de seis
    meses tiene derecho a saber que ese tramo falta.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    _escribir(cfg, "")
    eventos.ingerir(cfg)

    _escribir(cfg, ARRANQUE)
    eventos.ingerir(cfg)

    assert any("Faltan sucesos" in a for a in eventos.avisos(cfg))


# ------------------------------------------------ el historial ya rotado

# Lo que deja logrotate: '.1' en texto plano —por el delaycompress que pone el
# instalador— y del '.2' en adelante comprimidos.
VIEJO_1 = ("2026-07-20 09:00:00 192.168.1.50:40001 [daniel] Peer Connection "
           "Initiated with [AF_INET]192.168.1.50:40001\n")
VIEJO_2 = ("2026-06-01 08:00:00 192.168.1.77:40002 [marta] Peer Connection "
           "Initiated with [AF_INET]192.168.1.77:40002\n")


def _rotado(cfg, sufijo, texto):
    ruta = cfg.openvpn.log_path + sufijo
    if sufijo.endswith(".gz"):
        with gzip.open(ruta, "wb") as f:
            f.write(texto.encode("utf-8"))
    else:
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(texto)
    return ruta


def test_recupera_lo_que_quedo_en_los_archivos_rotados(cfg, base):
    """
    El caso de estrenar esto en un servidor que lleva meses en marcha: el log
    vivo es de esta semana y las ocho anteriores están en el disco, a punto de
    borrarse sin que nadie las haya leído.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    _rotado(cfg, ".1", VIEJO_1)
    _rotado(cfg, ".2.gz", VIEJO_2)

    resumen = eventos.importar_rotados(cfg)

    assert resumen["sucesos"] == 2
    assert resumen["avisos"] == []
    assert db.contar_eventos_vpn(base) == 3


def test_lo_recuperado_queda_por_debajo_y_no_arriba(cfg, base):
    """
    El id ordena la tabla. A unos sucesos que ocurrieron antes no se les puede
    dar un id mayor: saldrían los primeros, como si fueran lo último que ha
    pasado, y el historial quedaría del revés justo al recuperarlo.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    _rotado(cfg, ".1", VIEJO_1)
    _rotado(cfg, ".2.gz", VIEJO_2)

    eventos.importar_rotados(cfg)

    assert [e["ts"] for e in db.listar_eventos_vpn(base)] == [
        "2026-07-30 10:00:01",   # el que ya estaba, el más reciente
        "2026-07-20 09:00:00",
        "2026-06-01 08:00:00",
    ]


def test_importar_dos_veces_no_duplica(cfg, base):
    """
    Es idempotente sin llevar cuenta de qué archivos se leyeron —que además se
    renombran solos en cada rotación—: al terminar, el corte pasa a ser lo
    recién importado.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    _rotado(cfg, ".1", VIEJO_1)

    eventos.importar_rotados(cfg)
    segunda = eventos.importar_rotados(cfg)

    assert segunda["sucesos"] == 0
    assert db.contar_eventos_vpn(base) == 2


def test_no_vuelve_a_meter_lo_que_ya_trajo_la_ingesta(cfg, base):
    """
    El '.1' es copia del archivo vivo: si el rescate de una rotación ya se
    llevó su final, eso no puede entrar otra vez por la puerta de atrás.
    """
    _escribir(cfg, VIEJO_1 + CONEXION)
    eventos.ingerir(cfg)
    _rotado(cfg, ".1", VIEJO_1 + CONEXION)

    resumen = eventos.importar_rotados(cfg)

    assert resumen["sucesos"] == 0
    assert db.contar_eventos_vpn(base) == 2


def test_con_la_tabla_vacia_entra_todo(cfg, base):
    """Instalación nueva: no hay corte contra el que comparar"""
    _rotado(cfg, ".1", VIEJO_1)
    _rotado(cfg, ".2.gz", VIEJO_2)

    assert eventos.importar_rotados(cfg)["sucesos"] == 2


def test_lo_recuperado_se_purga_por_su_fecha_y_no_por_la_de_hoy(cfg, base):
    """
    Si `visto` fuera el momento de importar, una historia de hace un año
    quedaría marcada como leída hoy y la purga por antigüedad no se la
    llevaría nunca.
    """
    hace_un_ano = datetime.now() - timedelta(days=400)
    _rotado(cfg, ".1", "%s 192.168.1.50:40001 [daniel] Peer Connection "
                       "Initiated with [AF_INET]192.168.1.50:40001\n"
                       % hace_un_ano.strftime("%Y-%m-%d %H:%M:%S"))

    eventos.importar_rotados(cfg)

    assert db.purgar_eventos_vpn(base, 90) == 1


def test_sin_archivos_rotados_lo_dice(cfg, base):
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)

    resumen = eventos.importar_rotados(cfg)

    assert resumen["sucesos"] == 0
    assert any("No hay archivos rotados" in a for a in resumen["avisos"])


def test_si_lo_guardado_no_lleva_fecha_se_niega_y_explica(cfg, base):
    """
    Sin fechas no hay forma de saber qué parte de los archivos rotados ya
    entró, y meterlos enteros la duplicaría. Se dice, con el arreglo.
    """
    _escribir(cfg, "127.0.0.1:57176 [alfa2] Peer Connection Initiated with "
                   "[AF_INET]127.0.0.1:57176\n")
    eventos.ingerir(cfg)
    _rotado(cfg, ".1", VIEJO_1)

    resumen = eventos.importar_rotados(cfg)

    assert resumen["sucesos"] == 0
    assert any("fechas-log.sh" in a for a in resumen["avisos"])
    assert db.contar_eventos_vpn(base) == 1


def test_un_gz_ilegible_no_tira_abajo_a_los_demas(cfg, base):
    _rotado(cfg, ".1", VIEJO_1)
    with open(cfg.openvpn.log_path + ".2.gz", "wb") as f:
        f.write(b"esto no es un gzip")

    resumen = eventos.importar_rotados(cfg)

    assert resumen["sucesos"] == 1
    assert any("No se pudo leer" in a for a in resumen["avisos"])


def test_los_rotados_se_leen_del_mas_antiguo_al_mas_reciente(cfg):
    """
    El número sube con la antigüedad. Leerlos al revés desordenaría el
    historial y rompería la atribución de un rechazo a su CN, que depende de
    que las líneas de una sesión vayan seguidas.
    """
    for sufijo in (".1", ".2.gz", ".3.gz"):
        _rotado(cfg, sufijo, VIEJO_1)

    rotados = ev.archivos_rotados(cfg.openvpn.log_path)

    assert [os.path.basename(r) for r in rotados] == [
        "openvpn.log.3.gz", "openvpn.log.2.gz", "openvpn.log.1",
    ]


# --------------------------------------------------------- los avisos

def test_avisa_si_hay_log_pero_nada_reconocible(cfg, base):
    """
    Un 'verb' bajo no escribe estas líneas, y una tabla vacía se parecería a
    «no ha entrado nadie». Hay que decir cuál de las dos cosas es.
    """
    _escribir(cfg, "2026-07-30 10:00:00 us=1 Cipher negotiation enabled\n")
    eventos.ingerir(cfg)

    assert any("verb" in a for a in eventos.avisos(cfg))


def test_un_tramo_tranquilo_no_borra_el_aviso_anterior(cfg, base):
    """
    Con sucesos ya guardados, un tramo sin ninguno es lo más normal a media
    conexión: no significa que el 'verb' esté mal ni tiene que tapar lo que se
    dijo antes.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)

    _escribir(cfg, "2026-07-30 10:00:02 us=1 Cipher negotiation enabled\n", modo="a")
    eventos.ingerir(cfg)

    assert not any("verb" in a for a in eventos.avisos(cfg))


def test_si_nunca_se_ha_leido_el_log_se_dice(cfg, base):
    """
    Una tabla vacía en una instalación nueva se parece a una VPN sin visitas.
    Son cosas distintas y la segunda es un problema del panel.
    """
    _escribir(cfg, CONEXION)

    assert any("todavía no ha leído" in a for a in eventos.avisos(cfg))


def test_un_log_que_no_se_puede_leer_se_dice_aunque_haya_historial(cfg, base):
    """
    Comprobarlo en vivo y no solo al ingerir: con la tabla llena, un log que
    dejó de ser legible no se notaría hasta que alguien echara en falta una
    conexión de la semana pasada.
    """
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    os.remove(cfg.openvpn.log_path)

    assert db.contar_eventos_vpn(base) == 1
    assert any("log-append" in a for a in eventos.avisos(cfg))


def test_sin_log_no_se_toca_el_cursor(cfg, base):
    """Ingerir sin archivo no puede dejar el cursor en un sitio inventado"""
    assert eventos.ingerir(cfg) == 0
    assert db.obtener_ajuste(base, eventos.AJUSTE_CURSOR) is None


# ---------------------------------------------------------- consultas

def test_los_filtros_se_resuelven_en_sql(cfg, base):
    _escribir(cfg, ARRANQUE + CONEXION + DESCONEXION + RECHAZO)
    eventos.ingerir(cfg)

    assert db.contar_eventos_vpn(base, "todo") == 4
    assert db.contar_eventos_vpn(base, "conexiones") == 2
    assert db.contar_eventos_vpn(base, "fallos") == 1


def test_un_filtro_inventado_no_llega_al_sql(cfg, base):
    """
    Las condiciones se interpolan, así que se eligen por clave: un valor que no
    esté en la lista cae en 'todo' en vez de acercarse a la consulta.
    """
    _escribir(cfg, CONEXION + RECHAZO)
    eventos.ingerir(cfg)

    assert db.contar_eventos_vpn(base, "'; DROP TABLE eventos_vpn; --") == 2


def test_los_filtros_salen_de_los_mismos_conjuntos_que_mira_la_pantalla(cfg):
    """
    Escritos a mano, un tipo nuevo se añadiría en un sitio y el otro seguiría
    filtrando por la lista vieja sin que nada fallara.
    """
    for tipo in ev.FALLOS:
        assert "'%s'" % tipo in db.FILTROS_EVENTOS_VPN["fallos"]
    for tipo in ev.ENTRADAS_Y_SALIDAS:
        assert "'%s'" % tipo in db.FILTROS_EVENTOS_VPN["conexiones"]


# ------------------------------------------------------------- purga

def _envejecer(ruta, dias):
    """Deja todos los sucesos guardados como si se hubieran leído hace N días"""
    visto = (datetime.now(timezone.utc) - timedelta(days=dias)).isoformat()
    con = sqlite3.connect(ruta)
    try:
        con.execute("UPDATE eventos_vpn SET visto = ?", (visto,))
        con.commit()
    finally:
        con.close()


def test_la_purga_se_lleva_lo_viejo_y_deja_lo_reciente(cfg, base):
    _escribir(cfg, CONEXION)
    eventos.ingerir(cfg)
    _envejecer(base, 400)

    _escribir(cfg, DESCONEXION, modo="a")
    eventos.ingerir(cfg)

    assert db.purgar_eventos_vpn(base, 30) == 1
    assert [e["tipo"] for e in db.listar_eventos_vpn(base)] == [ev.DESCONEXION]


def test_la_purga_puede_llevarse_el_historial_entero(cfg, base):
    _escribir(cfg, CONEXION + DESCONEXION)
    eventos.ingerir(cfg)

    assert db.purgar_eventos_vpn(base, 0) == 2
    assert db.contar_eventos_vpn(base) == 0


def test_purgar_no_reingiere_lo_borrado(cfg, base):
    """
    El cursor no se mueve al purgar, y tiene que ser así: si volviera atrás, la
    vuelta siguiente reingeriría lo que se acaba de pedir borrar.
    """
    _escribir(cfg, CONEXION + DESCONEXION)
    eventos.ingerir(cfg)
    db.purgar_eventos_vpn(base, 0)

    eventos.ingerir(cfg)

    assert db.contar_eventos_vpn(base) == 0
