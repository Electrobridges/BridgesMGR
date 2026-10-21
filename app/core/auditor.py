"""
Auditoría de endurecimiento del server.conf.

Puntúa la configuración del servidor al estilo de ssh-audit o Lynis: cada
hallazgo dice qué pasa, por qué importa y cómo se arregla, con la línea que
hay que poner. Un informe que dice qué está mal pero no cómo se corrige obliga
a buscarlo fuera, que es justo lo que esto evita.

Solo LEE. No cambia el server.conf ni puede: el helper no lo escribe por
diseño (ver deploy/ovpn-web-helper), así que los arreglos los aplica una
persona. Solo stdlib y sin E/S: recibe las directivas que entrega el helper.

Los textos que se enseñan —el título y el porqué de cada hallazgo— van
marcados con N_() donde se crean y traducidos con t() cuando se arma el
informe. El arreglo es otra cosa: a veces es una directiva del server.conf (y
esa no se traduce nunca) y a veces es prosa (y esa sí). Las directivas no
están en el catálogo, así que t() las devuelve tal cual, sin cambios.
"""

import re

from ..idiomas import N_, t, tn
from . import serverconf as sc

CRITICO = "critico"
AVISO = "aviso"
SUGERENCIA = "sugerencia"
BIEN = "bien"

NIVELES = (CRITICO, AVISO, SUGERENCIA, BIEN)

# Cuánto resta cada nivel de los 100 puntos. Una nota sola no sustituye a leer
# la lista, pero ayuda a ver si un cambio la mejora o la empeora.
PESO = {CRITICO: 25, AVISO: 8, SUGERENCIA: 2, BIEN: 0}

CIFRADOS_DEBILES = re.compile(r'(^|[:-])(BF|DES|RC2|RC4|CAST5|DES-EDE3)(-|$)', re.I)
DIGESTS_DEBILES = {"MD5", "SHA1", "SHA", "RSA-MD5", "RSA-SHA1"}


def _h(nivel, clave, titulo, porque, arreglo=None, valores=None):
    """
    Un hallazgo.

    'titulo' y 'porque' son plantillas de texto con huecos con nombre; 'valores'
    lleva lo que se les mete. 'arreglo' es una directiva del server.conf o es
    prosa: las dos cosas se traducen al final, pero solo la prosa está en el
    catálogo.
    """
    return {"nivel": nivel, "clave": clave, "titulo": titulo,
            "porque": porque, "arreglo": arreglo, "valores": valores or {}}


def version_openvpn(texto):
    """'OpenVPN 2.6.3 x86_64-pc-linux-gnu […]' -> (2, 6, 3), o None."""
    m = re.match(r'^OpenVPN (\d+)\.(\d+)\.(\d+)', texto or "")
    return tuple(int(x) for x in m.groups()) if m else None


# Fallos con CVE que se pueden decidir solo con la versión y el server.conf.
# (desde, hasta_incluida, CVE, condición sobre las directivas o None, texto)
CVES = (
    ((2, 6, 0), (2, 6, 6), "CVE-2023-46850", None,
     N_("uso de memoria liberada que puede filtrar memoria del servidor o tumbarlo")),
    ((2, 6, 1), (2, 6, 13), "CVE-2025-2704", "tls-crypt-v2",
     N_("un cliente puede tumbar el servidor con paquetes tls-crypt-v2 manipulados")),
)


def _version(directivas, version):
    v = version_openvpn(version)
    if v is None:
        return [_h(SUGERENCIA, "version",
                   N_("No se pudo averiguar la versión de OpenVPN"),
                   N_("Sin ella no se pueden cruzar los fallos de seguridad conocidos."))]

    texto = "%d.%d.%d" % v
    hallazgos = []
    for desde, hasta, cve, condicion, que in CVES:
        if desde <= v <= hasta and (condicion is None or sc.tiene(directivas, condicion)):
            hallazgos.append(_h(
                CRITICO, "cve",
                N_("OpenVPN %(version)s está afectado por %(cve)s"),
                N_("Es vulnerable: %(detalle)s."),
                N_("Actualiza OpenVPN (apt update && apt install --only-upgrade openvpn)"),
                {"version": texto, "cve": cve, "detalle": t(que)},
            ))

    if v < (2, 5, 0):
        hallazgos.append(_h(
            AVISO, "version",
            N_("OpenVPN %(version)s es una rama antigua"),
            N_("No negocia cifrados (data-ciphers) y las correcciones de seguridad "
               "ya no llegan a esa rama."),
            N_("Actualiza a 2.6, que es la que traen Debian 12 y Ubuntu 24.04"),
            {"version": texto},
        ))
    elif v < (2, 6, 0):
        hallazgos.append(_h(
            SUGERENCIA, "version",
            N_("OpenVPN %(version)s: la rama 2.6 es la mantenida"),
            N_("Las correcciones de seguridad llegan primero a 2.6, y tls-crypt-v2 "
               "con claves por cliente necesita 2.6 en los dos extremos."),
            None,
            {"version": texto},
        ))
    elif not hallazgos:
        hallazgos.append(_h(BIEN, "version",
                            N_("OpenVPN %(version)s sin fallos conocidos que apliquen"),
                            N_("Ninguno de los CVE que revisa el panel afecta a esta versión "
                               "con esta configuración."),
                            None,
                            {"version": texto}))
    return hallazgos


def _canal_de_control(d):
    if sc.tiene(d, "tls-crypt-v2"):
        return [_h(BIEN, "tls",
                   N_("tls-crypt-v2: canal de control cifrado con clave por cliente"),
                   N_("Un perfil filtrado no compromete a los demás."))]
    if sc.tiene(d, "tls-crypt") or "<tls-crypt>" in [x[0] for x in d]:
        return [
            _h(BIEN, "tls",
               N_("tls-crypt: canal de control cifrado y autenticado"),
               N_("El servidor ni contesta a quien no tenga la clave, lo que lo hace "
                  "invisible a un escaneo y corta de raíz los ataques al handshake TLS.")),
            _h(SUGERENCIA, "tls-v2",
               N_("La clave tls-crypt es la misma en todos los perfiles"),
               N_("Quien se haga con un .ovpn tiene la clave de todos. Con tls-crypt-v2 "
                  "cada perfil lleva la suya; exige OpenVPN 2.6 en servidor y clientes."),
               "sudo bash deploy/migrar-tls-crypt-v2.sh"),
        ]
    if sc.tiene(d, "tls-auth") or "<tls-auth>" in [x[0] for x in d]:
        return [_h(AVISO, "tls",
                   N_("tls-auth autentica el canal de control pero no lo cifra"),
                   N_("tls-crypt hace lo mismo y además oculta el certificado del cliente "
                      "durante el handshake."),
                   N_("Cambia 'tls-auth ta.key 0' por 'tls-crypt <clave>' (y los perfiles)"))]
    return [_h(CRITICO, "tls",
               N_("Sin tls-crypt ni tls-auth"),
               N_("Cualquiera en internet puede iniciar un handshake TLS con el servidor: "
                  "es la puerta de los ataques de denegación de servicio y de los fallos "
                  "de OpenSSL antes de autenticar."),
               N_("openvpn --genkey secret /etc/openvpn/tls-crypt.key  y añade  "
                  "tls-crypt /etc/openvpn/tls-crypt.key"))]


def _cifrados(d):
    hallazgos = []
    data = sc.ultima(d, "data-ciphers") or sc.ultima(d, "ncp-ciphers")
    cipher = sc.ultima(d, "cipher")
    fallback = sc.ultima(d, "data-ciphers-fallback")

    lista = data[0] if data else ""
    if lista and CIFRADOS_DEBILES.search(lista):
        hallazgos.append(_h(CRITICO, "cifrado",
                            N_("data-ciphers admite cifrados rotos"),
                            N_("%(lista)s incluye algoritmos de bloque de 64 bits o retirados "
                               "(SWEET32)."),
                            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
                            {"lista": lista}))
    elif lista:
        hallazgos.append(_h(BIEN, "cifrado",
                            N_("Cifrados del canal de datos: %(lista)s"),
                            N_("Solo cifrados autenticados modernos."),
                            None,
                            {"lista": lista}))
    elif cipher and CIFRADOS_DEBILES.search(cipher[0]):
        hallazgos.append(_h(CRITICO, "cifrado",
                            N_("cipher %(cifrado)s es un cifrado roto"),
                            N_("Bloque de 64 bits: vulnerable a SWEET32."),
                            "data-ciphers AES-256-GCM:AES-128-GCM",
                            {"cifrado": cipher[0]}))
    else:
        hallazgos.append(_h(SUGERENCIA, "cifrado",
                            N_("Sin 'data-ciphers' explícito"),
                            N_("Se usan los de serie de esta versión. Declararlos deja claro "
                               "qué se negocia y evita sorpresas al actualizar."),
                            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"))

    for args, nombre in ((fallback, "data-ciphers-fallback"), (cipher, "cipher")):
        if args and "CBC" in args[0].upper() and not CIFRADOS_DEBILES.search(args[0]):
            hallazgos.append(_h(
                SUGERENCIA, "fallback",
                N_("%(directiva)s %(valor)s mantiene CBC para clientes antiguos"),
                N_("Solo lo necesitan clientes 2.3/2.4, que no negocian. Sin clientes así, "
                   "quitarlo deja el canal de datos solo en modo autenticado (GCM)."),
                N_("Quita '%(directiva)s' cuando todos los clientes sean 2.5 o posterior"),
                {"directiva": nombre, "valor": args[0]}))
            break
    return hallazgos


def _tls(d):
    hallazgos = []
    minimo = sc.ultima(d, "tls-version-min")
    if not minimo:
        hallazgos.append(_h(AVISO, "tls-min",
                            N_("Sin 'tls-version-min'"),
                            N_("Según la biblioteca TLS, podría aceptarse TLS 1.0 o 1.1."),
                            "tls-version-min 1.2"))
    elif minimo[0] in ("1.0", "1.1"):
        hallazgos.append(_h(AVISO, "tls-min",
                            N_("tls-version-min %(minimo)s admite TLS obsoleto"),
                            N_("TLS 1.0 y 1.1 están retirados (RFC 8996)."),
                            "tls-version-min 1.2",
                            {"minimo": minimo[0]}))
    else:
        hallazgos.append(_h(BIEN, "tls-min",
                            N_("TLS %(minimo)s como mínimo"),
                            N_("Nada por debajo de TLS 1.2."),
                            None,
                            {"minimo": minimo[0]}))

    if not sc.tiene(d, "tls-cert-profile"):
        hallazgos.append(_h(SUGERENCIA, "perfil",
                            N_("Sin 'tls-cert-profile'"),
                            N_("Con 'preferred' se rechazan certificados con firmas SHA1 o "
                               "claves RSA de menos de 2048 bits."),
                            "tls-cert-profile preferred"))

    auth = sc.ultima(d, "auth")
    if auth and auth[0].upper() in DIGESTS_DEBILES:
        hallazgos.append(_h(AVISO, "auth",
                            N_("auth %(algoritmo)s es un resumen débil"),
                            N_("Afecta al HMAC de tls-auth y a los cifrados no autenticados."),
                            "auth SHA256",
                            {"algoritmo": auth[0]}))

    reneg = sc.ultima(d, "reneg-sec")
    if reneg and reneg[0] == "0":
        hallazgos.append(_h(AVISO, "reneg",
                            N_("reneg-sec 0 desactiva la renegociación de claves"),
                            N_("La misma clave de sesión vive lo que dure la conexión, días si "
                               "hace falta."),
                            N_("Quita 'reneg-sec 0' (el de serie es 3600)")))
    return hallazgos


def _clientes(d):
    hallazgos = []
    if not sc.tiene(d, "crl-verify"):
        hallazgos.append(_h(CRITICO, "crl",
                            N_("Sin 'crl-verify': revocar no surte efecto"),
                            N_("El panel revoca certificados en la PKI, pero OpenVPN no consulta "
                               "la lista de revocación: el revocado sigue entrando."),
                            "crl-verify /etc/openvpn/easy-rsa/pki/crl.pem"))
    else:
        hallazgos.append(_h(BIEN, "crl",
                            N_("crl-verify activo"),
                            N_("Un certificado revocado deja de entrar en la siguiente conexión.")))

    if not (sc.tiene(d, "remote-cert-tls") or sc.tiene(d, "verify-x509-name")):
        hallazgos.append(_h(AVISO, "remote-cert",
                            N_("Sin 'remote-cert-tls client'"),
                            N_("Sin él, un certificado de servidor de la misma CA podría "
                               "presentarse como cliente."),
                            "remote-cert-tls client"))

    if sc.tiene(d, "duplicate-cn"):
        hallazgos.append(_h(AVISO, "duplicate-cn",
                            N_("'duplicate-cn' permite usar un perfil varias veces a la vez"),
                            N_("Un .ovpn copiado puede conectarse en paralelo al legítimo sin que "
                               "nadie se dé cuenta, y el panel deja de poder detectar perfiles "
                               "compartidos."),
                            N_("Quita 'duplicate-cn': cada persona, su certificado")))
    else:
        hallazgos.append(_h(BIEN, "duplicate-cn",
                            N_("Una sola sesión por certificado"),
                            N_("Si el mismo perfil conecta dos veces, OpenVPN cierra la sesión "
                               "anterior, y el panel lo registra como sesión desplazada.")))

    if sc.tiene(d, "client-to-client"):
        hallazgos.append(_h(AVISO, "client-to-client",
                            N_("'client-to-client' activo"),
                            N_("El tráfico entre clientes se conmuta dentro de OpenVPN y no pasa "
                               "por el cortafuegos del sistema: los destinos limitados por "
                               "cliente no se aplican entre clientes."),
                            N_("Quítalo si los clientes no necesitan verse entre sí")))

    modo = (sc.ultima(d, "verify-client-cert") or ["require"])[0]
    if modo in ("none", "optional"):
        hallazgos.append(_h(CRITICO, "cert-cliente",
                            N_("El certificado de cliente no es obligatorio"),
                            N_("Con 'verify-client-cert %(modo)s' se puede entrar sin certificado."),
                            N_("Quita 'verify-client-cert' o déjalo en 'require'"),
                            {"modo": modo}))
    return hallazgos


def _sistema(d):
    hallazgos = []
    user = sc.ultima(d, "user")
    if not user:
        hallazgos.append(_h(AVISO, "privilegios",
                            N_("OpenVPN sigue corriendo como root"),
                            N_("Sin 'user', un fallo en el proceso que atiende a los clientes es "
                               "un fallo con privilegios de root."),
                            N_("user nobody  y  group %(grupo)s  (más persist-key y persist-tun)"),
                            {"grupo": sc.GRUPO_VPN}))
    else:
        hallazgos.append(_h(BIEN, "privilegios",
                            N_("Suelta privilegios a '%(usuario)s'"),
                            N_("Tras arrancar ya no corre como root."),
                            None,
                            {"usuario": user[0]}))
        if not (sc.tiene(d, "persist-key") and sc.tiene(d, "persist-tun")):
            hallazgos.append(_h(AVISO, "persist",
                                N_("Falta persist-key o persist-tun"),
                                N_("Sin root, OpenVPN no puede volver a leer las claves ni a abrir "
                                   "el túnel al reiniciarse en caliente."),
                                N_("persist-key  y  persist-tun")))

    if sc.tiene(d, "comp-lzo") or sc.tiene(d, "compress"):
        permitida = (sc.ultima(d, "allow-compression") or [""])[0]
        if permitida != "no":
            hallazgos.append(_h(CRITICO, "compresion",
                                N_("Compresión activa en el túnel"),
                                N_("Comprimir antes de cifrar filtra información del contenido "
                                   "(VORACLE)."),
                                N_("Quita 'compress'/'comp-lzo' y añade 'allow-compression no'")))

    nivel = sc.ultima(d, "script-security")
    if nivel and nivel[0] == "3":
        hallazgos.append(_h(AVISO, "script-security",
                            N_("script-security 3"),
                            N_("Pasa las contraseñas de los clientes a los scripts por variables "
                               "de entorno. El panel solo necesita el nivel 2."),
                            "script-security 2"))

    mgmt = sc.ultima(d, "management")
    if mgmt and mgmt[0] not in ("127.0.0.1", "localhost", "::1") and not mgmt[0].startswith("/"):
        hallazgos.append(_h(CRITICO, "management",
                            N_("El management escucha en %(host)s"),
                            N_("Quien llegue a ese puerto puede expulsar clientes y ver quién "
                               "está conectado, sin contraseña."),
                            "management 127.0.0.1 %(puerto)s",
                            {"host": mgmt[0],
                             "puerto": mgmt[1] if len(mgmt) > 1 else "7505"}))

    verb = sc.ultima(d, "verb")
    if verb and verb[0].isdigit() and int(verb[0]) < 3:
        hallazgos.append(_h(AVISO, "verb",
                            N_("verb %(nivel)s: el log no registra las conexiones"),
                            N_("El historial de la VPN del panel se queda vacío y no hay rastro "
                               "de quién entró ni de quién fue rechazado."),
                            "verb 3",
                            {"nivel": verb[0]}))

    faltan = sc.dos_pasos(d)
    if not faltan:
        hallazgos.append(_h(BIEN, "dos-pasos",
                            N_("Verificación en dos pasos disponible"),
                            N_("Se puede exigir un código de la app del móvil a cada cliente "
                               "desde sus políticas.")))
    else:
        hallazgos.append(_h(SUGERENCIA, "dos-pasos",
                            N_("La VPN no puede pedir un segundo factor"),
                            N_("Con él, un .ovpn robado no basta para entrar: hace falta "
                               "también el móvil de su dueño. Solo se pide a los clientes que "
                               "lo tengan activado."),
                            N_("%(directivas)s  y  auth-gen-token 0"),
                            {"directivas": "  ".join(faltan)}))

    enganchado, motivo = sc.gancho(d)
    if enganchado:
        hallazgos.append(_h(BIEN, "politicas",
                            N_("Script de políticas enganchado"),
                            N_("Horarios, caducidades e IP fijas se deciden al conectar.")))
    else:
        # El motivo viene de serverconf, que lo marca con N_() para poder
        # traducirlo. Se enseña traducido, como el resto del informe.
        hallazgos.append(_h(AVISO, "politicas",
                            N_("Políticas por cliente a medias: %(motivo)s"),
                            N_("El vigilante expulsa a quien se quede fuera, pero su cliente "
                               "vuelve a entrar en segundos."),
                            N_("script-security 2  y  client-connect %(hook)s"),
                            {"motivo": t(motivo), "hook": sc.HOOK_CLIENT_CONNECT}))
    return hallazgos


def auditar(directivas, version="", crl_dias=None):
    """
    Devuelve {'hallazgos': [...], 'nota': int, 'cuentas': {nivel: n}}.

    Los hallazgos van ordenados de más grave a menos. 'crl_dias' son los días
    que le quedan a la CRL, si se pudieron leer.
    """
    hallazgos = (
        _version(directivas, version)
        + _canal_de_control(directivas)
        + _cifrados(directivas)
        + _tls(directivas)
        + _clientes(directivas)
        + _sistema(directivas)
    )

    if crl_dias is not None:
        if crl_dias < 0:
            hallazgos.append(_h(CRITICO, "crl-fecha",
                                N_("La CRL ha caducado"),
                                N_("OpenVPN rechaza TODAS las conexiones, no solo las revocadas."),
                                N_("Revoca o restaura cualquier cliente desde el panel para "
                                   "regenerarla")))
        elif crl_dias < 30:
            hallazgos.append(_h(AVISO, "crl-fecha",
                                # Con plural de verdad: 'en 1 días' no vale ni en
                                # español ni en inglés.
                                tn("La CRL caduca en %(dias)s día",
                                   "La CRL caduca en %(dias)s días", crl_dias),
                                N_("Al caducar, OpenVPN rechazará a todo el mundo."),
                                N_("Revoca o restaura cualquier cliente desde el panel para "
                                   "regenerarla"),
                                {"dias": crl_dias}))

    # Los textos que se enseñan van traducidos. El arreglo se traduce también,
    # pero las directivas del server.conf no están en el catálogo y salen
    # tal cual, sin cambios.
    for h in hallazgos:
        valores = h.pop("valores")
        h["titulo"] = t(h["titulo"], **valores)
        h["porque"] = t(h["porque"], **valores)
        if h["arreglo"]:
            h["arreglo"] = t(h["arreglo"], **valores)

    orden = {n: i for i, n in enumerate(NIVELES)}
    hallazgos.sort(key=lambda h: orden[h["nivel"]])

    cuentas = {n: sum(1 for h in hallazgos if h["nivel"] == n) for n in NIVELES}
    nota = max(0, 100 - sum(PESO[h["nivel"]] for h in hallazgos))
    return {"hallazgos": hallazgos, "nota": nota, "cuentas": cuentas}
