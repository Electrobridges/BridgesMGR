"""
Vigilante de la salud del servidor.

Las categorías de seguridad y certificados avisan colgadas de auditar(): pasan
porque alguien hace algo. Esta no —nadie provoca que una CRL caduque— así que
hay que ir a mirar, y lo que más importa es que **no se convierta en ruido**:
un aviso diario durante seis meses se ignora igual que no avisar.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app import db, notificar, vigilante
from app.core import salud


# ----------------------------------------------------------- los umbrales

@pytest.mark.parametrize("dias,esperado", [
    # Con holgura no hay nada que decir
    (365, None), (60, None), (31, None),
    # Cruzado el de 30, ese es el escalón en el que se está
    (30, 30), (20, 30),
    (14, 14), (10, 14),
    (7, 7), (5, 7),
    (3, 3), (2, 3),
    (1, 1), (0, 1),
    # Caducada: escalón 0, el más urgente que hay
    (-1, 0), (-90, 0),
])
def test_el_umbral_que_corresponde(dias, esperado):
    assert salud.umbral_cruzado(dias) == esperado


def test_devuelve_el_escalon_mas_ajustado():
    """
    El escalón es el umbral más pequeño que todavía no se ha rebasado: con 10
    días se está "por debajo de 14", no "por debajo de 30". Así, un panel que
    lleva un mes sin mirarse avisa del escalón real y no del más tranquilo.
    """
    assert salud.umbral_cruzado(10) == 14
    assert salud.umbral_cruzado(20) == 30


# --------------------------------------------------- lectura de la CRL

def test_sin_ruta_lo_dice(tmp_path):
    with pytest.raises(salud.SinCRL):
        salud.caducidad_crl("")


def test_si_no_existe_lo_dice(tmp_path):
    with pytest.raises(salud.SinCRL) as e:
        salud.caducidad_crl(str(tmp_path / "no-existe.pem"))
    assert "No existe" in str(e.value)


def test_un_archivo_que_no_es_crl_no_revienta(tmp_path):
    """
    Devolver un error claro y no una excepción cualquiera: esto corre en un
    hilo de fondo y un fallo raro ahí se traga sin que nadie lo vea.
    """
    basura = tmp_path / "basura.pem"
    basura.write_text("esto no es una CRL", encoding="utf-8")

    with pytest.raises(salud.SinCRL):
        salud.caducidad_crl(str(basura))


@pytest.mark.parametrize("texto,anio", [
    ("Jan 25 23:48:26 2027 GMT", 2027),
    ("Sep 26 13:21:48 2035 GMT", 2035),
])
def test_entiende_el_formato_de_openssl(texto, anio):
    assert salud._a_fecha(texto).year == anio


def test_una_fecha_rara_no_pasa_por_buena():
    with pytest.raises(salud.SinCRL):
        salud._a_fecha("el martes que viene")


# ------------------------------------------------- no repetirse

@pytest.fixture
def avisos(monkeypatch, cfg, usuarios):
    """Captura los avisos sin enviarlos ni tocar la red"""
    caja = []
    monkeypatch.setattr(notificar, "avisar",
                        lambda c, cat, asunto, cuerpo, grave=False:
                        caja.append((cat, asunto, cuerpo, grave)) or True)
    return caja


def _crl_que_caduca_en(monkeypatch, dias):
    fecha = datetime.now(timezone.utc) + timedelta(days=dias, hours=1)
    monkeypatch.setattr(salud, "caducidad_crl",
                        lambda ruta, ahora=None: (fecha, dias))


def test_avisa_al_cruzar_el_umbral(monkeypatch, cfg, avisos):
    _crl_que_caduca_en(monkeypatch, 20)

    vigilante._revisar_crl(cfg)

    assert len(avisos) == 1
    categoria, asunto, cuerpo, _ = avisos[0]
    assert categoria == notificar.SERVICIO
    assert "20 día" in asunto
    assert "TODAS las conexiones" in cuerpo
    assert "gen-crl" in cuerpo, "el aviso tiene que decir cómo arreglarlo"


def test_no_repite_el_mismo_umbral(monkeypatch, cfg, avisos):
    """
    Lo que separa un aviso útil de un buzón que se filtra a la papelera: con
    180 días de validez, avisar en cada vuelta serían miles de correos.
    """
    _crl_que_caduca_en(monkeypatch, 20)

    for _ in range(5):
        vigilante._revisar_crl(cfg)

    assert len(avisos) == 1


def test_vuelve_a_avisar_al_bajar_de_escalon(monkeypatch, cfg, avisos):
    _crl_que_caduca_en(monkeypatch, 20)
    vigilante._revisar_crl(cfg)

    _crl_que_caduca_en(monkeypatch, 5)
    vigilante._revisar_crl(cfg)

    assert len(avisos) == 2
    assert "5 día" in avisos[1][1]


def test_no_avisa_con_holgura(monkeypatch, cfg, avisos):
    _crl_que_caduca_en(monkeypatch, 200)

    vigilante._revisar_crl(cfg)

    assert avisos == []


def test_regenerar_la_crl_rearma_el_aviso(monkeypatch, cfg, avisos):
    """
    Tras regenerarla vuelve a haber holgura. Si no se rearmara, el siguiente
    vencimiento —dentro de otros 180 días— pasaría en silencio.
    """
    _crl_que_caduca_en(monkeypatch, 5)
    vigilante._revisar_crl(cfg)

    _crl_que_caduca_en(monkeypatch, 180)
    vigilante._revisar_crl(cfg)
    assert db.obtener_ajuste(cfg.seguridad.db_path, vigilante.AJUSTE_CRL, "x") == ""

    _crl_que_caduca_en(monkeypatch, 5)
    vigilante._revisar_crl(cfg)
    assert len(avisos) == 2


def test_caducada_avisa_en_pasado_y_como_grave(monkeypatch, cfg, avisos):
    _crl_que_caduca_en(monkeypatch, -3)

    vigilante._revisar_crl(cfg)

    _, asunto, cuerpo, grave = avisos[0]
    assert "HA CADUCADO" in asunto
    assert grave is True
    assert "Nadie puede entrar" in cuerpo


def test_una_crl_ilegible_no_llena_el_buzon(monkeypatch, cfg, avisos):
    """
    Sin CRL legible el problema es otro y ya lo canta el comprobador. Avisar
    aquí sería un correo cada cinco minutos en una instalación a medio montar.
    """
    def falla(ruta, ahora=None):
        raise salud.SinCRL("no existe")
    monkeypatch.setattr(salud, "caducidad_crl", falla)

    vigilante._revisar_crl(cfg)

    assert avisos == []


# ------------------------------------------------- el servicio

def _servicio(monkeypatch, activo):
    from app.core import easyrsa
    monkeypatch.setattr(easyrsa, "estado_servicio",
                        lambda c: {"activo": activo,
                                   "estado": "active" if activo else "inactive"})


def test_la_primera_vuelta_solo_anota(monkeypatch, cfg, avisos):
    """
    Reiniciar el panel con el servicio ya caído no es una novedad: avisar ahí
    convertiría cada reinicio en una alarma.
    """
    _servicio(monkeypatch, False)

    vigilante._revisar_servicio(cfg)

    assert avisos == []
    assert db.obtener_ajuste(cfg.seguridad.db_path, vigilante.AJUSTE_SERVICIO) == "caido"


def test_avisa_al_caerse(monkeypatch, cfg, avisos):
    _servicio(monkeypatch, True)
    vigilante._revisar_servicio(cfg)

    _servicio(monkeypatch, False)
    vigilante._revisar_servicio(cfg)

    assert len(avisos) == 1
    _, asunto, _, grave = avisos[0]
    assert "NO está corriendo" in asunto
    assert grave is True


def test_avisa_al_volver(monkeypatch, cfg, avisos):
    _servicio(monkeypatch, True)
    vigilante._revisar_servicio(cfg)
    _servicio(monkeypatch, False)
    vigilante._revisar_servicio(cfg)

    _servicio(monkeypatch, True)
    vigilante._revisar_servicio(cfg)

    assert len(avisos) == 2
    assert "ha vuelto" in avisos[1][1]


def test_mientras_siga_igual_no_repite(monkeypatch, cfg, avisos):
    _servicio(monkeypatch, True)
    vigilante._revisar_servicio(cfg)
    _servicio(monkeypatch, False)

    for _ in range(5):
        vigilante._revisar_servicio(cfg)

    assert len(avisos) == 1


def test_una_revision_que_falla_no_mata_a_la_otra(monkeypatch, cfg, avisos):
    """
    El vigilante corre en un hilo de fondo: si una excepción lo matara, se
    quedaría sin vigilancia justo lo que existe para vigilar.
    """
    def revienta(c):
        raise RuntimeError("boom")
    monkeypatch.setattr(vigilante, "_revisar_crl", revienta)
    _servicio(monkeypatch, True)
    vigilante._revisar_servicio(cfg)
    _servicio(monkeypatch, False)

    vigilante._vuelta(cfg)

    assert len(avisos) == 1, "la segunda revisión tiene que ejecutarse igual"
