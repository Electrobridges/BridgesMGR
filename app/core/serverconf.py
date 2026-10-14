"""
Lectura del server.conf a partir de lo que devuelve el helper.

El panel no puede abrir el archivo (0600 root); el helper se lo pasa troceado
en directivas y sin material de clave. Aquí se interpreta: qué red reparte,
dónde está el pool dinámico, si el script de políticas está enganchado.

Solo stdlib y sin E/S: se le pasa la lista y se prueba sin servidor.
"""

import ipaddress

HOOK_CLIENT_CONNECT = "/usr/local/lib/ovpn-web/client-connect"


def ultima(directivas, nombre):
    """Los argumentos de la última aparición, que es la que gana. None si no está."""
    encontrada = None
    for d in directivas:
        if d and d[0] == nombre:
            encontrada = d[1:]
    return encontrada


def todas(directivas, nombre):
    return [d[1:] for d in directivas if d and d[0] == nombre]


def tiene(directivas, nombre):
    return ultima(directivas, nombre) is not None


def red(directivas):
    """
    {'red', 'servidor', 'pool', 'topologia', 'libres'} o None.

    'libres' es el tramo de la red que queda fuera del pool dinámico y se
    puede usar para IP fijas, como (primera, última), o None si no queda.
    Lo mismo que calcula el helper, que es quien de verdad lo hace cumplir.
    """
    server = ultima(directivas, "server")
    if not server or len(server) < 2:
        return None
    try:
        net = ipaddress.IPv4Network("%s/%s" % (server[0], server[1]), strict=False)
    except ValueError:
        return None

    pool = None
    explicito = ultima(directivas, "ifconfig-pool")
    if explicito and len(explicito) >= 2:
        try:
            pool = (ipaddress.IPv4Address(explicito[0]), ipaddress.IPv4Address(explicito[1]))
        except ValueError:
            pool = None
    elif not (len(server) >= 3 and server[2] == "nopool"):
        pool = (net.network_address + 2, net.broadcast_address - 2)

    topologia = (ultima(directivas, "topology") or ["net30"])[0]

    primera = net.network_address + 2
    ultima_ip = net.broadcast_address - 1
    libres = None
    if pool is None:
        libres = (primera, ultima_ip)
    elif pool[1] < ultima_ip:
        libres = (max(pool[1] + 1, primera), ultima_ip)
    elif pool[0] > primera:
        libres = (primera, pool[0] - 1)

    return {
        "red": net,
        "servidor": net.network_address + 1,
        "pool": pool,
        "topologia": topologia,
        "libres": libres,
    }


def gancho(directivas):
    """
    Si el script de políticas del panel está enganchado, y si no, por qué.

    Devuelve (bool, motivo). Sin él, las políticas solo se aplican expulsando
    por el management, y quien es expulsado vuelve a entrar en segundos.
    """
    cc = ultima(directivas, "client-connect")
    if not cc:
        return False, "el server.conf no tiene 'client-connect'"
    if cc[0] != HOOK_CLIENT_CONNECT:
        return False, "'client-connect' apunta a otro script (%s)" % cc[0]
    nivel = ultima(directivas, "script-security")
    if not nivel or nivel[0] not in ("2", "3"):
        return False, "falta 'script-security 2', y sin él OpenVPN no ejecuta el script"
    return True, None
