"""
Invariantes de la mitad privilegiada.

Ni el helper, ni la regla de sudo, ni la unidad de systemd se pueden ejercitar
fuera de un servidor Debian real: hacen falta root, easyrsa y una PKI de
verdad. Lo que sí se puede comprobar desde aquí es que nadie ha roto por
descuido las reglas que sostienen la frontera de privilegios.

Son comprobaciones de texto sobre los archivos de deploy/, deliberadamente
literales. Si tocas uno de esos archivos y una de estas pruebas falla, piensa
por qué antes de ajustar la prueba: casi siempre la prueba tiene razón.
"""

import ast
import re
from pathlib import Path

import pytest

from app.core import validacion

RAIZ = Path(__file__).resolve().parents[1]
DEPLOY = RAIZ / "deploy"
HELPER = DEPLOY / "ovpn-web-helper"
SUDOERS = DEPLOY / "ovpnweb.sudoers"
SERVICIO = DEPLOY / "ovpn-web.service"
INSTALADOR = DEPLOY / "install.sh"
INSTALA_VPN = DEPLOY / "instalar-openvpn.sh"
EJEMPLO = DEPLOY / "config.ejemplo.yaml"


def _leer(ruta):
    assert ruta.is_file(), "Falta %s" % ruta.name
    return ruta.read_text(encoding="utf-8")


# ---------------------------------------------------------------- el helper

def test_el_helper_compila():
    """Sintaxis del helper: es lo único que corre como root"""
    compile(_leer(HELPER), str(HELPER), "exec")


def test_regex_de_cn_identico_a_los_dos_lados():
    """
    El helper revalida el CN por su cuenta porque no se fía del panel. Si los
    dos regex divergen, existe un nombre que un lado acepta y el otro no, y la
    frontera deja de significar lo mismo en cada lado.
    """
    m = re.search(r"^CN_RE\s*=\s*re\.compile\(r'(.+)'\)\s*$", _leer(HELPER), re.M)
    assert m, "No se encuentra CN_RE en el helper"
    assert m.group(1) == validacion._CN_RE.pattern


def test_reservados_identicos_a_los_dos_lados():
    m = re.search(r"^RESERVADOS\s*=\s*\{(.+)\}\s*$", _leer(HELPER), re.M)
    assert m, "No se encuentra RESERVADOS en el helper"

    nombres = {t.strip().strip("'\"") for t in m.group(1).split(",") if t.strip()}
    assert nombres == validacion._RESERVADOS


def test_longitud_maxima_identica_a_los_dos_lados():
    assert "len(cn) > 64" in _leer(HELPER)


def test_el_helper_no_acepta_rutas_por_argumento():
    """
    Regla 1: las rutas salen de /etc/ovpn-web/config.yaml, que es root:ovpnweb
    0640. Si el helper las tomara de argv, un panel comprometido apuntaría
    easyrsa a un binario propio y sería root.
    """
    fuente = _leer(HELPER)
    assert 'CONFIG = "/etc/ovpn-web/config.yaml"' in fuente

    # argv solo se usa para el subcomando y el CN, nunca para construir rutas
    for linea in fuente.splitlines():
        if "sys.argv" in linea and not linea.lstrip().startswith("#"):
            assert "path" not in linea.lower() and "ruta" not in linea.lower(), (
                "Sospechoso: sys.argv usado cerca de una ruta -> %s" % linea.strip()
            )


@pytest.mark.parametrize("archivo", [
    HELPER,
    *sorted((RAIZ / "app").rglob("*.py")),
])
def test_nunca_shell_true(archivo):
    """
    Regla 5: subprocess siempre con lista de argumentos.

    Se mira el árbol sintáctico y no el texto: así una mención en un docstring
    ('jamás shell=True') no cuenta como infracción, y una llamada real no se
    escapa por estar partida en varias líneas.
    """
    arbol = ast.parse(_leer(archivo), str(archivo))

    for nodo in ast.walk(arbol):
        if not isinstance(nodo, ast.Call):
            continue
        for kw in nodo.keywords:
            if kw.arg == "shell":
                assert not (isinstance(kw.value, ast.Constant) and kw.value.value), (
                    "shell=True en %s, línea %d" % (archivo.name, nodo.lineno)
                )


# ---------------------------------------------------------------- sudoers

def test_sudoers_solo_autoriza_el_helper():
    """
    Regla 2: no autorizar easyrsa. Acepta --pki-dir y --vars, así que una regla
    con comodines sobre él equivale a regalar root.
    """
    reglas = [
        l.strip() for l in _leer(SUDOERS).splitlines()
        if l.strip() and not l.strip().startswith(("#", "Defaults"))
    ]

    assert reglas == [
        "ovpnweb ALL=(root) NOPASSWD: /usr/local/sbin/ovpn-web-helper"
    ], "La regla de sudo ha cambiado; revisa que no amplíe lo autorizado"


def test_sudoers_sin_comodines():
    for regla in _leer(SUDOERS).splitlines():
        if regla.strip().startswith("#"):
            continue
        assert "*" not in regla, "Un comodín en sudoers convierte el panel en root"
        assert "easyrsa" not in regla.lower()


# ---------------------------------------------------------------- systemd

def test_servicio_no_activa_nonewprivileges():
    """
    Regla 4: sudo es setuid. Activar NoNewPrivileges parece un endurecimiento
    razonable y rompe toda la gestión de certificados sin decir por qué.
    """
    assert re.search(r"^NoNewPrivileges=false\s*$", _leer(SERVICIO), re.M)


def test_servicio_corre_sin_privilegios():
    fuente = _leer(SERVICIO)
    assert re.search(r"^User=ovpnweb\s*$", fuente, re.M)
    assert not re.search(r"^User=root\s*$", fuente, re.M)


# --------------------------------------------------- montar el servidor VPN

def _config_ejemplo():
    """El YAML de ejemplo, sin traerse PyYAML solo para esto"""
    valores = {}
    for linea in _leer(EJEMPLO).splitlines():
        m = re.match(r'^\s{2,}([a-z_]+):\s*"?([^"#]*?)"?\s*(?:#.*)?$', linea)
        if m:
            valores[m.group(1)] = m.group(2)
    return valores


@pytest.mark.parametrize("clave", [
    "log_path", "status_path", "mgmt_host", "mgmt_port", "easyrsa_path", "tls_crypt",
])
def test_lo_que_monta_el_script_es_lo_que_espera_el_panel(clave):
    """
    Paridad entre lo que instalar-openvpn.sh deja escrito y lo que
    config.ejemplo.yaml dice que va a encontrar.

    Si divergen, el panel se instala "correctamente" y luego no ve conexiones,
    o revoca contra una PKI que no es la que usa el servidor. Es un fallo mudo,
    de los que se descubren el día que hace falta cortarle el acceso a alguien.
    """
    valor = _config_ejemplo()[clave]
    assert valor, "config.ejemplo.yaml no define %s" % clave
    assert valor in _leer(INSTALA_VPN), (
        "%s vale %r en config.ejemplo.yaml y no aparece en instalar-openvpn.sh"
        % (clave, valor)
    )


def test_el_script_escribe_el_formato_de_status_que_se_parsea():
    """
    parse_status_text() solo entiende el v3. Con cualquier otro el panel lee un
    archivo lleno de datos y no encuentra ni una conexión.
    """
    fuente = _leer(INSTALA_VPN)
    assert re.search(r"^status-version 3\s*$", fuente, re.M)


def test_el_script_activa_el_management():
    """Sin él solo queda el archivo de status, que va con hasta 5 s de retraso"""
    valores = _config_ejemplo()
    esperado = "management %s %s" % (valores["mgmt_host"], valores["mgmt_port"])
    fuente = _leer(INSTALA_VPN)

    assert "management ${MGMT_HOST} ${MGMT_PORT}" in fuente
    assert "MGMT_HOST=%s" % valores["mgmt_host"] in fuente
    assert "MGMT_PORT=%s" % valores["mgmt_port"] in fuente, esperado


def test_el_script_verifica_la_crl():
    """
    Sin crl-verify el panel revoca certificados y el revocado sigue entrando.
    Es la diferencia entre cortar un acceso y creer que lo has cortado.
    """
    assert re.search(r"^crl-verify ", _leer(INSTALA_VPN), re.M)


@pytest.mark.parametrize("funcion", ["cmd_revocar", "cmd_restaurar"])
def test_el_helper_deja_la_crl_legible_tras_regenerarla(funcion):
    """
    OpenVPN relee la CRL en cada conexión, y para entonces ya bajó a 'nobody'.
    Si gen-crl la deja en 0600, revocar deja el servidor sin admitir a nadie:
    el panel diría que ha cortado un acceso y habría cortado todos.

    Se mira el árbol sintáctico para no contar la propia definición ni una
    mención en un comentario.
    """
    arbol = ast.parse(_leer(HELPER), str(HELPER))

    cuerpo = next(
        (n for n in ast.walk(arbol)
         if isinstance(n, ast.FunctionDef) and n.name == funcion),
        None,
    )
    assert cuerpo, "No existe %s en el helper" % funcion

    llamadas = {
        n.func.id for n in ast.walk(cuerpo)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "asegurar_crl_legible" in llamadas, (
        "%s regenera la CRL y no se asegura de dejarla legible" % funcion
    )


def test_el_script_no_pisa_un_servidor_existente():
    """
    Idempotencia: relanzarlo en una máquina con OpenVPN montado no puede
    reescribir su server.conf ni su PKI.
    """
    fuente = _leer(INSTALA_VPN)
    assert 'if [[ -f "$SERVER_CONF" ]]; then' in fuente
    assert 'if [[ -f "$EASYRSA_DIR/pki/ca.crt" ]]; then' in fuente


def test_las_claves_privadas_siguen_fuera_del_alcance_del_panel():
    """
    El script relaja permisos en la PKI para que 'nobody' lea la CRL. Eso no
    puede acabar abriendo private/, que es donde está la clave de la CA.
    """
    fuente = _leer(INSTALA_VPN)
    assert 'chmod 0700 "$EASYRSA_DIR/pki/private"' in fuente


def test_el_instalador_del_panel_no_monta_la_vpn_por_su_cuenta():
    """
    Son dos trabajos con riesgos distintos: uno sostiene la frontera de
    privilegios y el otro toca el encaminamiento de la máquina. install.sh
    puede llamar al otro script, pero no reimplementarlo.
    """
    fuente = _leer(INSTALADOR)
    assert "bash deploy/instalar-openvpn.sh" in fuente
    for prohibido in ("easyrsa", "init-pki", "masquerade", "ip_forward"):
        assert prohibido not in fuente.lower(), (
            "install.sh está montando la VPN por su cuenta: %r" % prohibido
        )


# ------------------------------------ lo que enseñó el primer servidor real
#
# Los cuatro fallos de aquí abajo se encontraron desplegando en un Debian 13 de
# verdad, no leyendo el código. Ninguno se veía desde Windows y los cuatro
# rompían el panel entero, así que cada uno se queda con su prueba.

def test_el_servicio_puede_escribir_en_la_pki():
    """
    ProtectSystem=strict monta el sistema en solo lectura dentro del espacio de
    nombres del servicio, y los hijos lo heredan — también el helper lanzado
    con sudo, aunque corra como root. Sin /etc/openvpn en ReadWritePaths el
    panel no puede emitir, revocar ni restaurar un solo certificado, que es
    para lo que existe. Y falla con un error de easyrsa que no menciona systemd
    por ningún lado, así que cuesta media tarde llegar hasta aquí.
    """
    fuente = _leer(SERVICIO)
    assert re.search(r"^ProtectSystem=strict\s*$", fuente, re.M), (
        "Si se relaja ProtectSystem, revisa si esta prueba sigue teniendo sentido"
    )

    m = re.search(r"^ReadWritePaths=(.+)$", fuente, re.M)
    assert m, "La unidad no declara ReadWritePaths"
    escribibles = m.group(1).split()

    pki = _config_ejemplo()["easyrsa_path"]
    assert any(pki == ruta or pki.startswith(ruta.rstrip("/") + "/") for ruta in escribibles), (
        "La PKI (%s) no está en ReadWritePaths (%s): el panel no podrá tocarla"
        % (pki, " ".join(escribibles))
    )


def test_el_helper_llama_a_easyrsa_en_modo_desatendido():
    """
    easy-rsa 3.2 empezó a pedir confirmación también en build-client-full. Sin
    --batch el helper se queda esperando una respuesta que nadie va a dar y el
    panel no emite ni un certificado en Debian 13. Las versiones anteriores no
    preguntaban: el fallo aparece al actualizar el sistema, no al tocar esto.
    """
    arbol = ast.parse(_leer(HELPER), str(HELPER))

    funcion = next(
        (n for n in ast.walk(arbol)
         if isinstance(n, ast.FunctionDef) and n.name == "correr_easyrsa"),
        None,
    )
    assert funcion, "No existe correr_easyrsa en el helper"

    constantes = {
        n.value for n in ast.walk(funcion)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    assert "--batch" in constantes, "correr_easyrsa no pasa --batch a easyrsa"


def test_el_helper_no_se_traga_el_error_de_easyrsa():
    """
    easy-rsa escribe separadores decorativos ('-----') en stderr y el motivo
    real en stdout. Quedarse con stderr cuando no está vacío hacía que el panel
    dijera '-----' y nada más. Los errores se muestran, no se decoran.
    """
    arbol = ast.parse(_leer(HELPER), str(HELPER))

    funcion = next(
        (n for n in ast.walk(arbol)
         if isinstance(n, ast.FunctionDef) and n.name == "correr_easyrsa"),
        None,
    )
    atributos = {
        n.attr for n in ast.walk(funcion)
        if isinstance(n, ast.Attribute)
    }
    assert {"stdout", "stderr"} <= atributos, (
        "El fallo de easyrsa debe reportar los dos flujos, no uno"
    )


def test_el_hash_de_htmx_esta_versionado():
    """
    HTMX se sirve desde el propio panel, así que la CSP `script-src 'self'` lo
    da por bueno: un archivo manipulado por el CDN sería JavaScript corriendo
    con la sesión del administrador. Lo único que lo impide es comparar contra
    un hash conocido, y para eso el hash tiene que viajar EN el repo.

    Estuvo sin versionar: el instalador guardaba lo que devolviera unpkg.com y
    lo daba por bueno, así que cada instalación desde un clon limpio confiaba a
    ciegas en una red ajena.
    """
    hash_htmx = DEPLOY / "htmx.sha256"

    assert hash_htmx.is_file(), (
        "Falta deploy/htmx.sha256: sin él la instalación acepta lo que dé el CDN"
    )

    contenido = hash_htmx.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{64}", contenido), (
        "deploy/htmx.sha256 debe ser un único SHA-256 en hexadecimal: %r" % contenido
    )

    # Y que no esté bloqueado por .gitignore, que es como se quedó fuera
    ignorados = _leer(RAIZ / ".gitignore")
    assert "htmx.sha256" not in ignorados, ".gitignore no puede excluir el hash"


def test_sin_hash_el_instalador_aborta():
    """
    La rama sin hash tiene que ABORTAR, no guardar lo que venga. Aceptar a
    ciegas un script de una red ajena es exactamente lo que la verificación
    existe para evitar.
    """
    fuente = _leer(INSTALADOR)

    assert "HTMX_CONFIAR" in fuente, "debe hacer falta una opción explícita"
    # La rama que fija el hash sin verificar va detrás de esa opción
    m = re.search(r"^elif \[\[ \"\$HTMX_CONFIAR\" == \"1\" \]\]; then$", fuente, re.M)
    assert m, "guardar el hash debe depender de --htmx-confiar"


def test_la_contrasena_del_certificado_nunca_va_por_argv():
    """
    argv es público: cualquiera con una cuenta en el servidor puede leer la
    línea de comandos de un proceso ajeno con un 'ps' en el momento justo. La
    contraseña del cliente entra al helper por stdin y sale hacia easyrsa por
    el entorno, que solo lee su dueño o root.

    Si algún día alguien "simplifica" esto a --passout=pass:..., la contraseña
    de cada certificado emitido queda al alcance de cualquier usuario del
    servidor durante el segundo que dura la emisión.
    """
    fuente = _leer(HELPER)

    assert "--passout=env:" in fuente, "la contraseña debe ir por el entorno"
    assert "passout=pass:" not in fuente, "eso pondría la contraseña en argv"
    assert "sys.stdin.read()" in fuente, "la contraseña debe entrar por stdin"

    # El cuarto argumento es una marca fija, no el secreto
    assert 'MARCA_CLAVE = "con-clave"' in fuente

    arbol = ast.parse(fuente, str(HELPER))
    lector = next(
        (n for n in ast.walk(arbol)
         if isinstance(n, ast.FunctionDef) and n.name == "leer_clave_de_stdin"),
        None,
    )
    assert lector, "no existe leer_clave_de_stdin"
    assert "sys" in ast.dump(lector), "debe leer de sys.stdin, no de argv"


def test_la_marca_de_contrasena_coincide_a_los_dos_lados():
    """
    El panel manda la marca y el helper la compara. Si divergen, el helper
    rechaza la petición y no se puede emitir ni un certificado cifrado.
    """
    from app.core import easyrsa as cliente

    m = re.search(r'^MARCA_CLAVE = "(.+)"\s*$', _leer(HELPER), re.M)
    assert m, "No se encuentra MARCA_CLAVE en el helper"
    assert m.group(1) == cliente.MARCA_CLAVE


def test_el_minimo_de_la_contrasena_coincide_a_los_dos_lados():
    """El helper revalida por su cuenta: el panel no es de fiar desde ese lado"""
    from app.core import easyrsa as cliente

    m = re.search(r"^MIN_CLAVE = (\d+)\s*$", _leer(HELPER), re.M)
    assert m, "No se encuentra MIN_CLAVE en el helper"
    assert int(m.group(1)) == cliente.MIN_CLAVE


def test_el_cn_de_la_ca_no_contamina_al_resto():
    """
    EASYRSA_REQ_CN puesto en 'vars' se aplica a TODAS las peticiones, no solo a
    la de la CA: el certificado del servidor y el de cada cliente salían con el
    CN de la CA. Deja una PKI con varios certificados del mismo nombre, un
    índice inservible y un panel incapaz de identificar a nadie. El CN de la CA
    va como opción de la orden que la construye, y solo ahí.
    """
    fuente = _leer(INSTALA_VPN)

    assert "set_var EASYRSA_REQ_CN" not in fuente, (
        "EASYRSA_REQ_CN en vars contamina el CN de todos los certificados"
    )
    assert re.search(r"--req-cn=.*build-ca", fuente), (
        "El CN de la CA debe ir en la propia orden build-ca"
    )


@pytest.mark.parametrize("archivo", sorted(
    p for p in DEPLOY.iterdir() if p.is_file()
))
def test_sin_crlf_en_deploy(archivo):
    """
    Un CRLF llega al servidor como 'bad interpreter: /bin/bash^M' y cuesta
    media hora entenderlo. La CI ya lo mira; aquí se ve al escribirlo.
    """
    assert b"\r\n" not in archivo.read_bytes(), (
        "%s tiene finales de línea CRLF" % archivo.name
    )
