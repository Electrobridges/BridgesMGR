#!/usr/bin/env bash
#
# Monta un servidor OpenVPN desde cero, ya configurado para OpenVPN Manager Web.
#
#   sudo bash deploy/instalar-openvpn.sh --salida lan --host vpn.ejemplo.com
#
# Lo invoca deploy/install.sh cuando no encuentra un servidor montado, pero se
# puede lanzar suelto: es idempotente y no pisa nada que ya exista. Si encuentra
# una PKI la conserva; si encuentra un server.conf no lo toca y lo dice.
#
# Va aparte del instalador del panel a propósito. install.sh sostiene la
# frontera de privilegios —usuario sin permisos, helper, sudoers— y conviene
# que siga cabiendo de una lectura. Esto de aquí monta una VPN, que es otro
# trabajo y con otros riesgos: toca el encaminamiento de la máquina.
#
# Lo que deja, y que el panel espera encontrar tal cual:
#
#   /etc/openvpn/easy-rsa          PKI (private/ solo root)
#   /etc/openvpn/server/server.conf
#   /etc/openvpn/tls-crypt.key
#   /var/log/openvpn/status.log    formato v3, que es el que parsea el panel
#   /var/log/openvpn/openvpn.log
#   management en 127.0.0.1:7505
#   unidad openvpn-server@server

# -E para que la trampa de ERR también salte dentro de las funciones.
set -Eeuo pipefail

# ----------------------------------------------------------------- constantes
EASYRSA_DIR=/etc/openvpn/easy-rsa
SERVER_DIR=/etc/openvpn/server
SERVER_CONF="$SERVER_DIR/server.conf"
TLS_CRYPT=/etc/openvpn/tls-crypt.key
LOG_DIR=/var/log/openvpn
STATUS_FILE="$LOG_DIR/status.log"
LOG_FILE="$LOG_DIR/openvpn.log"
UNIDAD=openvpn-server@server
NFT_FILE=/etc/openvpn/ovpn-web-nat.nft
NAT_UNIDAD=/etc/systemd/system/ovpn-web-nat.service
SYSCTL_FILE=/etc/sysctl.d/99-ovpn-web-forward.conf

MGMT_HOST=127.0.0.1
MGMT_PORT=7505

# Lo instala también install.sh; se pone aquí para que OpenVPN no arranque con
# una directiva client-connect que apunta a un archivo que todavía no existe,
# que rechazaría a todo el mundo hasta terminar de instalar el panel.
HOOK_CLIENT_CONNECT=/usr/local/lib/ovpn-web/client-connect
VERIFICAR_TOTP=/usr/local/lib/ovpn-web/verificar-totp
GRUPO_VPN=ovpnweb-vpn
ESTADO_TOTP=/var/lib/ovpn-web-vpn

# ----------------------------------------------------------------- opciones
SALIDA=""              # lan | todo
HOST_CLIENTES=""
PUERTO=1194
PROTO=udp
RED_VPN=10.8.0.0/24
IFACE=""
RED_LAN=""
DNS1=9.9.9.9
DNS2=149.112.112.112
SIN_RED=0
SIN_ARRANCAR=0
ASUMIR_SI=0

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

# Mismo trato de fallos que install.sh: lo que impide montar el servidor para
# y dice en qué paso, en qué línea y qué mirar; lo que no lo impide avisa,
# sigue y se repite al final. Volver a lanzarlo es siempre seguro.
PASO="preparación"
PISTA=""
AVISOS=()

paso() { PASO=$1; PISTA=""; info "$1"; }
aviso_final() { amar "  AVISO: $1"; AVISOS+=("$1"); }

al_fallar() {
  local codigo=$1 linea=$2 orden=$3
  trap - ERR
  echo
  rojo "════════ EL MONTAJE DEL SERVIDOR SE HA DETENIDO ════════"
  echo "  Paso:     $PASO"
  echo "  Línea:    $linea de deploy/instalar-openvpn.sh"
  echo "  Orden:    $orden"
  echo "  Código:   $codigo"
  [[ -n $PISTA ]] && echo "  Qué mirar: $PISTA"
  echo
  echo "  Corregido el motivo, vuelve a lanzarlo: continúa donde se quedó y no"
  echo "  rehace lo que ya está (la PKI, la clave tls-crypt, el server.conf)."
  exit "$codigo"
}
trap 'al_fallar $? $LINENO "$BASH_COMMAND"' ERR

morir() {
  PISTA=${2:-$PISTA}
  rojo "$1"
  al_fallar 1 "${BASH_LINENO[0]}" "(comprobación del script) $1"
}

# Marca de los server.conf que escribe este script. Con ella se distingue un
# servidor ajeno —que no se toca— de uno que montó este mismo script y se
# quedó a medias: ese se termina de montar al volver a lanzarlo.
MARCA_PROPIA="# Generado por deploy/instalar-openvpn.sh"

uso() {
  cat <<'FIN'
Uso: sudo bash deploy/instalar-openvpn.sh [opciones]

  --salida lan|todo   Qué alcanza un cliente conectado:
                        lan  = solo la red local del servidor (túnel dividido)
                        todo = también su tráfico a internet (túnel completo)
                      Si no se indica, se pregunta.
  --host <destino>    Dirección por la que los clientes llegan al servidor
                      (IP pública o dominio). Se detecta si se puede.
  --puerto <n>        Puerto de la VPN (por defecto 1194)
  --proto udp|tcp     Protocolo (por defecto udp)
  --red <CIDR>        Red interna de la VPN (por defecto 10.8.0.0/24)
  --iface <nombre>    Interfaz de salida para el NAT (se detecta)
  --red-lan <CIDR>    Red local que se empuja con --salida lan (se detecta)
  --dns <a> <b>       DNS que se empujan con --salida todo
  --sin-red           No tocar reenvío IP, NAT ni cortafuegos
  --sin-arrancar      Dejarlo todo escrito sin habilitar ni arrancar la unidad
  --si                No preguntar nada
  -h, --help          Esta ayuda
FIN
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --salida)   SALIDA="${2:-}"; shift 2 ;;
    --host)     HOST_CLIENTES="${2:-}"; shift 2 ;;
    --puerto)   PUERTO="${2:-}"; shift 2 ;;
    --proto)    PROTO="${2:-}"; shift 2 ;;
    --red)      RED_VPN="${2:-}"; shift 2 ;;
    --iface)    IFACE="${2:-}"; shift 2 ;;
    --red-lan)  RED_LAN="${2:-}"; shift 2 ;;
    --dns)      DNS1="${2:-}"; DNS2="${3:-}"; shift 3 ;;
    --sin-red)       SIN_RED=1; shift ;;
    --sin-arrancar)  SIN_ARRANCAR=1; shift ;;
    --si)       ASUMIR_SI=1; shift ;;
    -h|--help)  uso; exit 0 ;;
    *)          rojo "Opción desconocida: $1"; uso; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { rojo "Ejecuta como root"; exit 1; }
command -v apt-get >/dev/null || { rojo "Este script es para Debian/Ubuntu"; exit 1; }

# ------------------------------------------------------------- comprobaciones
# Antes de instalar nada: si ya hay un servidor montado por otro, no es asunto
# nuestro. Si lo montó este script y se quedó a medias —un fallo de red, un
# sysctl que no carga—, se termina: si no, relanzarlo tras un fallo decía «no
# se toca» y salía en verde con el servidor sin NAT y sin arrancar.
CONF_PROPIA=0
if [[ -f "$SERVER_CONF" ]] && head -1 "$SERVER_CONF" | grep -qF "$MARCA_PROPIA"; then
  CONF_PROPIA=1
  info "$SERVER_CONF lo escribió este script: se continúa el montaje sin reescribirlo"
  # La red de la VPN sale del server.conf que ya hay, no de las opciones: el
  # NAT tiene que cuadrar con lo que OpenVPN reparte de verdad.
  RED_CONF=$(awk '$1 == "server" {print $2 "/" $3}' "$SERVER_CONF" | tail -1)
  if [[ -n $RED_CONF ]]; then
    RED_VPN=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' "$RED_CONF")
  fi
elif [[ -f "$SERVER_CONF" ]]; then
  amar "Ya existe $SERVER_CONF: no se toca."
  echo "  Este script solo monta un servidor nuevo. Para adaptar uno que ya"
  echo "  funciona, ajusta /etc/ovpn-web/config.yaml a mano — el panel necesita"
  echo "  que tu server.conf tenga al menos estas dos líneas:"
  echo
  echo "      management $MGMT_HOST $MGMT_PORT"
  echo "      status $STATUS_FILE 5"
  echo "      status-version 3"
  echo
  exit 0
fi

# ------------------------------------------------------------------- paquetes
# Solo si falta algo: relanzarlo sin red para apt no tiene por qué fallar.
paso "Instalando OpenVPN y easy-rsa"
FALTAN=()
for paquete in openvpn easy-rsa iproute2 nftables python3 curl ca-certificates; do
  dpkg -s "$paquete" >/dev/null 2>&1 || FALTAN+=("$paquete")
done
if (( ${#FALTAN[@]} )); then
  PISTA="apt no puede descargar: revisa la red y /etc/apt/sources.list, o instala a mano: apt-get install ${FALTAN[*]}"
  apt-get update -qq
  apt-get install -y --no-install-recommends "${FALTAN[@]}"
else
  verde "Ya están instalados"
fi

command -v openvpn >/dev/null || morir "No se pudo instalar openvpn"

ORIGEN_EASYRSA=""
for candidato in /usr/share/easy-rsa /usr/share/easy-rsa3; do
  [[ -x "$candidato/easyrsa" ]] && { ORIGEN_EASYRSA="$candidato"; break; }
done
[[ -n "$ORIGEN_EASYRSA" ]] || { rojo "No se encuentra easyrsa tras instalar easy-rsa"; exit 1; }

# ------------------------------------------------------------------ detección
# python3 ya es requisito del panel, así que se usa para la aritmética de redes
# en vez de hacer malabares con máscaras en bash.
cidr_a_red_y_mascara() {
  python3 -c 'import ipaddress,sys
r = ipaddress.ip_network(sys.argv[1], strict=False)
print(r.network_address, r.netmask)' "$1"
}

if [[ -z "$IFACE" ]]; then
  IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)
fi
[[ -n "$IFACE" ]] || { rojo "No se detecta la interfaz de salida; pásala con --iface"; exit 1; }

if [[ -z "$RED_LAN" ]]; then
  RED_LAN=$(ip -4 -o route show dev "$IFACE" scope link 2>/dev/null | awk '{print $1; exit}' || true)
fi

IP_LAN=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1 || true)

if [[ -z "$HOST_CLIENTES" ]]; then
  # Sin salida a internet esto falla, y es lo normal en una LAN: se cae a la IP
  # local y que lo corrija quien instala. Nunca se inventa un valor en silencio.
  HOST_CLIENTES=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  HOST_CLIENTES=${HOST_CLIENTES:-${IP_LAN:-}}
fi

# --------------------------------------------------------------- modo de salida
if [[ -z "$SALIDA" ]]; then
  if [[ "$ASUMIR_SI" == "1" ]]; then
    SALIDA=lan
  else
    echo
    echo "¿Qué debe alcanzar un cliente conectado a la VPN?"
    echo "  1) Solo la red local del servidor  (${RED_LAN:-no detectada})"
    echo "     Su tráfico a internet sigue saliendo por su propia conexión."
    echo "  2) Todo su tráfico, también internet"
    echo "     El servidor pasa a ser la salida a internet de cada cliente."
    read -rp "Elige [1/2] (1): " respuesta
    case "${respuesta:-1}" in
      2) SALIDA=todo ;;
      *) SALIDA=lan ;;
    esac
  fi
fi

case "$SALIDA" in
  lan|todo) ;;
  *) rojo "--salida solo admite 'lan' o 'todo'"; exit 1 ;;
esac

if [[ "$SALIDA" == "lan" && -z "$RED_LAN" ]]; then
  rojo "No se detecta la red local; indícala con --red-lan 192.168.1.0/24"
  exit 1
fi

case "$PROTO" in udp|tcp) ;; *) rojo "--proto solo admite 'udp' o 'tcp'"; exit 1 ;; esac
[[ "$PUERTO" =~ ^[0-9]+$ ]] || { rojo "--puerto debe ser un número"; exit 1; }

read -r RED_VPN_DIR RED_VPN_MASK <<<"$(cidr_a_red_y_mascara "$RED_VPN")"

# El pool dinámico se queda con las tres cuartas partes bajas de la red y deja
# el resto para las IP fijas que se asignen desde el panel. Con el pool que
# monta 'server' a secas —toda la red— una IP fija acabaría repartida también
# a otro cliente, y el helper se niega a asignarla.
pool_dinamico() {
  python3 -c 'import ipaddress,sys
r = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = r.num_addresses - 2
print(r.network_address + 2, r.network_address + max(2, hosts * 3 // 4))' "$1"
}
read -r POOL_INI POOL_FIN <<<"$(pool_dinamico "$RED_VPN")"

# ------------------------------------------------------------------- resumen
echo
echo "  Servidor VPN a montar"
echo "  ---------------------------------------------------------------"
printf '  %-22s %s\n' "Escucha en"            "$PROTO/$PUERTO"
printf '  %-22s %s\n' "Los clientes llegan a" "${HOST_CLIENTES:-<SIN DETERMINAR>}"
printf '  %-22s %s\n' "Red interna VPN"       "$RED_VPN"
printf '  %-22s %s\n' "Interfaz de salida"    "$IFACE"
if [[ "$SALIDA" == "lan" ]]; then
  printf '  %-22s %s\n' "Alcance del cliente" "la red local $RED_LAN"
else
  printf '  %-22s %s\n' "Alcance del cliente" "todo su tráfico (DNS $DNS1, $DNS2)"
fi
if [[ "$SIN_RED" == "1" ]]; then
  printf '  %-22s %s\n' "Red del servidor" "no se toca (--sin-red)"
else
  printf '  %-22s %s\n' "Red del servidor" "se activa reenvío IP y NAT"
fi
echo "  ---------------------------------------------------------------"
echo

if [[ -z "$HOST_CLIENTES" ]]; then
  amar "No se ha podido determinar por dónde llegan los clientes."
  echo "  Se dejará vacío y habrá que ponerlo en /etc/ovpn-web/config.yaml"
  echo "  (cliente_ovpn.remote_host) antes de repartir ningún perfil."
  echo
fi

if [[ "$ASUMIR_SI" != "1" ]]; then
  read -rp "¿Seguimos? [s/N]: " confirmar
  [[ "${confirmar,,}" == "s" || "${confirmar,,}" == "si" ]] || { echo "Cancelado."; exit 1; }
fi

# ----------------------------------------------------------------------- PKI
if [[ -f "$EASYRSA_DIR/pki/ca.crt" ]]; then
  info "Ya hay una PKI en $EASYRSA_DIR: se conserva"
else
  info "Creando la PKI en $EASYRSA_DIR"
  mkdir -p "$EASYRSA_DIR"
  cp -r "$ORIGEN_EASYRSA/." "$EASYRSA_DIR/"

  # Curva elíptica en vez de RSA: evita generar parámetros Diffie-Hellman
  # —que son los minutos que se lleva una instalación de OpenVPN— y da una
  # clave más fuerte. Necesita OpenVPN 2.4 o superior, de 2018.
  # EASYRSA_REQ_CN NO va aquí. Puesto en vars se aplica a TODAS las peticiones,
  # no solo a la de la CA: el certificado del servidor y el de cada cliente
  # saldrían con el CN de la CA. Se comprobó en un servidor real, donde dejaba
  # una PKI con dos certificados del mismo nombre, el índice inservible y el
  # panel incapaz de identificar a nadie. El CN de la CA va como opción de la
  # orden que la construye, y solo ahí.
  cat > "$EASYRSA_DIR/vars" <<FIN
set_var EASYRSA_ALGO        ec
set_var EASYRSA_CURVE       secp384r1
set_var EASYRSA_CA_EXPIRE   3650
set_var EASYRSA_CERT_EXPIRE 825
set_var EASYRSA_CRL_DAYS    3650
FIN

  (
    cd "$EASYRSA_DIR"
    ./easyrsa --batch init-pki
    ./easyrsa --batch --req-cn="OpenVPN Manager Web CA" build-ca nopass
    ./easyrsa --batch build-server-full server nopass
    ./easyrsa --batch gen-crl
  )
  verde "PKI creada"
fi

# La CRL la lee OpenVPN en cada conexión DESPUÉS de bajar a 'nobody', así que
# tiene que ser legible y los directorios atravesables. Las claves privadas no:
# private/ se queda en 0700 y ahí no entra ni el panel.
chmod 0755 "$EASYRSA_DIR" "$EASYRSA_DIR/pki"
chmod 0700 "$EASYRSA_DIR/pki/private"

if [[ -f "$EASYRSA_DIR/pki/crl.pem" ]]; then
  chmod 0644 "$EASYRSA_DIR/pki/crl.pem"
else
  rojo "gen-crl no ha dejado ninguna CRL: sin ella revocar no surtiría efecto"
  exit 1
fi

# ----------------------------------------------------------------- tls-crypt
if [[ -f "$TLS_CRYPT" ]]; then
  info "Ya existe $TLS_CRYPT: se conserva"
else
  info "Generando la clave tls-crypt"
  # La sintaxis cambió en OpenVPN 2.5; se intenta la nueva y se cae a la vieja.
  openvpn --genkey secret "$TLS_CRYPT" 2>/dev/null \
    || openvpn --genkey --secret "$TLS_CRYPT"
  chmod 0600 "$TLS_CRYPT"
fi

# --------------------------------------------------------------------- logs
info "Preparando $LOG_DIR"
mkdir -p "$LOG_DIR"
chown root:adm "$LOG_DIR"
chmod 0750 "$LOG_DIR"

# Se crean vacíos con dueño y permisos correctos ANTES de arrancar: OpenVPN los
# abre siendo root y luego solo los trunca, así que conserva estos permisos. Es
# lo que permite que el panel los lea por el grupo 'adm' sin ser privilegiado.
for archivo in "$STATUS_FILE" "$LOG_FILE"; do
  [[ -f "$archivo" ]] || install -o root -g adm -m 0640 /dev/null "$archivo"
done

# Con log-append y sin rotación, openvpn.log crece sin límite. El status.log no
# entra: OpenVPN lo reescribe entero cada pocos segundos y no crece.
#
# copytruncate y no el rotado normal, por el mismo motivo que el comentario de
# arriba: rotar renombrando obliga a avisar al demonio para que reabra, y a
# OpenVPN se le avisa con SIGHUP —que reinicia el túnel y desconecta a todo el
# mundo. Una rotación semanal no puede costar eso. Truncando en el sitio, el
# proceso sigue escribiendo en el mismo descriptor y el archivo conserva su
# dueño y sus permisos, que es lo que deja al panel leerlo por el grupo 'adm'.
LOGROTATE=/etc/logrotate.d/ovpn-web
if [[ ! -f "$LOGROTATE" ]]; then
  info "Instalando rotación de $LOG_FILE"
  cat > "$LOGROTATE" <<FIN
${LOG_FILE} {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
FIN
  chmod 0644 "$LOGROTATE"
fi

# --------------------------------------------------------------- server.conf
# Si ya es nuestro no se reescribe: puede tener cambios a mano, y lo que se
# está haciendo es terminar un montaje, no rehacerlo.
if [[ "$CONF_PROPIA" == "1" ]]; then
  info "Se conserva $SERVER_CONF"
else
paso "Escribiendo $SERVER_CONF"
mkdir -p "$SERVER_DIR"

{
  cat <<FIN
# Generado por deploy/instalar-openvpn.sh de OpenVPN Manager Web.
#
# Tres líneas de aquí NO son opcionales para el panel:
#   management ${MGMT_HOST} ${MGMT_PORT}  — de dónde saca quién está conectado
#   status ... 5                          — el archivo de respaldo si el
#                                           management no responde
#   status-version 3                      — el ÚNICO formato que parsea
#
# Si cambias alguna, cámbiala también en /etc/ovpn-web/config.yaml.

port ${PUERTO}
proto ${PROTO}
dev tun

ca   ${EASYRSA_DIR}/pki/ca.crt
cert ${EASYRSA_DIR}/pki/issued/server.crt
key  ${EASYRSA_DIR}/pki/private/server.key
dh   none
tls-crypt ${TLS_CRYPT}

# La CRL es lo que hace que revocar surta efecto. Sin esta línea el panel
# revoca certificados y el revocado sigue entrando.
crl-verify ${EASYRSA_DIR}/pki/crl.pem

topology subnet
# 'nopool' + un pool explícito: lo que queda por encima de ${POOL_FIN} es para
# las IP fijas que se asignan desde el panel (Clientes VPN → Políticas).
server ${RED_VPN_DIR} ${RED_VPN_MASK} nopool
ifconfig-pool ${POOL_INI} ${POOL_FIN} ${RED_VPN_MASK}
ifconfig-pool-persist ${LOG_DIR}/ipp.txt

# Políticas por cliente del panel: horario, caducidad e IP fija se deciden al
# conectar. El script lo instala el panel en una ruta de root que el propio
# panel no puede escribir, y corre como 'nobody'.
script-security 2
client-connect ${HOOK_CLIENT_CONNECT}

# Verificación en dos pasos, solo para los clientes que la tengan activada en
# el panel: con 'auth-user-pass-optional', un perfil sin 'auth-user-pass'
# llega al script con la contraseña vacía y, si su CN no tiene secreto, entra.
# 'auth-gen-token' evita pedir el código en cada renegociación de claves.
auth-user-pass-verify ${VERIFICAR_TOTP} via-file
auth-user-pass-optional
auth-gen-token 0

keepalive 10 120
persist-key
persist-tun
user nobody
# Grupo propio y no 'nogroup': es el único que puede leer los secretos de la
# verificación en dos pasos (/etc/openvpn/ovpn-web/totp-vpn.json). Con
# 'nogroup' los leería cualquier otro servicio que corra con ese grupo.
group ${GRUPO_VPN}

data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
auth SHA256
tls-version-min 1.2
tls-cert-profile preferred
remote-cert-tls client

# Solo en el bucle local. Cualquiera con una sesión en esta máquina puede
# hablar con el management, así que no des cuentas de shell en el servidor VPN.
management ${MGMT_HOST} ${MGMT_PORT}

status ${STATUS_FILE} 5
status-version 3
log-append ${LOG_FILE}
verb 3
FIN

  if [[ "$SALIDA" == "lan" ]]; then
    read -r LAN_DIR LAN_MASK <<<"$(cidr_a_red_y_mascara "$RED_LAN")"
    cat <<FIN

# Túnel dividido: se le enseña al cliente la ruta de la red local y nada más.
# Su tráfico a internet no pasa por aquí.
push "route ${LAN_DIR} ${LAN_MASK}"
FIN
  else
    cat <<FIN

# Túnel completo: todo el tráfico del cliente sale por este servidor.
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${DNS1}"
push "dhcp-option DNS ${DNS2}"
FIN
  fi
} > "$SERVER_CONF"
fi

chown root:root "$SERVER_CONF"
chmod 0600 "$SERVER_CONF"

# ------------------------------------------------------------------- red
if [[ "$SIN_RED" == "1" ]]; then
  amar "Reenvío IP y NAT sin tocar (--sin-red)."
  echo "  Los clientes conectarán, pero no encaminarán a ningún sitio hasta que"
  echo "  actives esto a mano:"
  echo "      echo 'net.ipv4.ip_forward=1' > $SYSCTL_FILE && sysctl -p $SYSCTL_FILE"
  echo "      nft add table ip ovpnweb"
  echo "      nft 'add chain ip ovpnweb postrouting { type nat hook postrouting priority srcnat; }'"
  echo "      nft add rule ip ovpnweb postrouting ip saddr $RED_VPN oifname \"$IFACE\" masquerade"
else
  paso "Activando el reenvío IP"
  echo "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
  # Solo NUESTRO archivo, no 'sysctl --system': ese recarga todos los del
  # sistema, y uno ajeno que no cargue —un módulo que falta, un contenedor que
  # no deja tocar cierta clave— paraba el montaje a medias. Pasó probándolo.
  if ! sysctl -q -p "$SYSCTL_FILE"; then
    if [[ $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) == 1 ]]; then
      aviso_final "sysctl no pudo cargar $SYSCTL_FILE, pero el reenvío IP ya estaba activo."
    else
      aviso_final "No se pudo activar el reenvío IP: los clientes conectarán pero no llegarán a la red. Actívalo a mano: sysctl -w net.ipv4.ip_forward=1"
    fi
  fi

  paso "Instalando la regla de NAT"
  PISTA="nftables rechazó la regla: ¿hay otro cortafuegos (firewalld, iptables-legacy) gestionando la máquina? Prueba con --sin-red y monta el NAT a mano."
  # Tabla propia y con nombre: así se ve de quién es, y borrarla no se lleva
  # por delante las reglas de nadie más. El 'delete' inicial la hace
  # reaplicable sin duplicar, y el '|| true' cubre la primera vez, cuando
  # todavía no existe.
  cat > "$NFT_FILE" <<FIN
#!/usr/sbin/nft -f
# NAT de OpenVPN Manager Web. Tabla aparte para no pisar las reglas de nadie.
add table ip ovpnweb
delete table ip ovpnweb
table ip ovpnweb {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr ${RED_VPN} oifname "${IFACE}" masquerade
    }
}
FIN
  chmod 0644 "$NFT_FILE"

  cat > "$NAT_UNIDAD" <<FIN
[Unit]
Description=NAT de OpenVPN Manager Web
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${NFT_FILE}
ExecStop=/usr/sbin/nft delete table ip ovpnweb

[Install]
WantedBy=multi-user.target
FIN

  systemctl daemon-reload
  systemctl enable --now ovpn-web-nat.service >/dev/null
  verde "NAT activo y persistente entre reinicios"

  # ufw filtra el reenvío en un enganche distinto al del NAT, así que la tabla
  # de arriba no basta: hay que decírselo a él en su idioma.
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    info "ufw está activo: abriendo el puerto y permitiendo el reenvío"
    ufw allow "$PUERTO/$PROTO" >/dev/null
    ufw route allow in on tun0 out on "$IFACE" >/dev/null
    [[ "$SALIDA" == "lan" ]] || ufw route allow in on "$IFACE" out on tun0 >/dev/null
    verde "Reglas de ufw añadidas"
  fi
fi

# ---------------------------------------------------------- fechas del log
# Sin marca de tiempo en el log, el panel no puede decir cuánto duró una
# sesión. El porqué y el cómo están en fechas-log.sh, que es el mismo que usa
# install.sh: una sola copia de la lógica no se desincroniza.
#
# Sin --reiniciar porque la unidad se arranca unas líneas más abajo, y no tiene
# sentido reiniciar dos veces.
bash "$(dirname "$0")/fechas-log.sh" "$UNIDAD"

# ------------------------------------------------------- script de políticas
info "Instalando el script de políticas en $HOOK_CLIENT_CONNECT"
install -d -o root -g root -m 0755 "$(dirname "$HOOK_CLIENT_CONNECT")"
install -o root -g root -m 0755 "$(dirname "$0")/ovpn-web-client-connect" "$HOOK_CLIENT_CONNECT"
install -o root -g root -m 0755 "$(dirname "$0")/ovpn-web-verificar-totp" "$VERIFICAR_TOTP"

# El grupo con el que corre OpenVPN, y donde el script de dos pasos anota el
# último código aceptado de cada cliente para que no valga dos veces.
getent group "$GRUPO_VPN" >/dev/null || groupadd --system "$GRUPO_VPN"
install -d -o root -g "$GRUPO_VPN" -m 0770 "$ESTADO_TOTP"

# --------------------------------------------------------------------- unidad
paso "Arrancando OpenVPN"
if [[ "$SIN_ARRANCAR" == "1" ]]; then
  amar "Todo escrito, sin arrancar (--sin-arrancar). Cuando quieras:"
  echo "    systemctl enable --now $UNIDAD"
else
  info "Arrancando $UNIDAD"
  systemctl enable "$UNIDAD" >/dev/null
  systemctl restart "$UNIDAD"

  sleep 2
  if systemctl is-active --quiet "$UNIDAD"; then
    verde "OpenVPN en marcha"
  else
    # Con 'log-append' OpenVPN escribe sus errores en su log y no en el
    # journal, que se queda casi vacío: se enseña lo que de verdad dijo.
    rojo "OpenVPN no ha arrancado. Lo último de $LOG_FILE:"
    tail -n 15 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || true
    morir "OpenVPN no arranca con la configuración montada." \
      "El error está justo encima. Más contexto: journalctl -u $UNIDAD -n 40 --no-pager"
  fi
fi

# Estos valores los lee install.sh para rellenar config.yaml sin adivinarlos.
cat > /run/ovpn-web-instalacion.env <<FIN
OVPN_REMOTE_HOST=${HOST_CLIENTES}
OVPN_REMOTE_PUERTO=${PUERTO}
OVPN_PROTO=${PROTO}
OVPN_UNIDAD=${UNIDAD}
FIN
chmod 0600 /run/ovpn-web-instalacion.env

echo
verde "Servidor OpenVPN montado."
echo
printf '  %-22s %s\n' "Configuración"  "$SERVER_CONF"
printf '  %-22s %s\n' "PKI"            "$EASYRSA_DIR"
printf '  %-22s %s\n' "Estado (v3)"    "$STATUS_FILE"
printf '  %-22s %s\n' "Unidad"         "$UNIDAD"
echo
if [[ -z "$HOST_CLIENTES" ]]; then
  amar "Falta poner cliente_ovpn.remote_host en /etc/ovpn-web/config.yaml."
fi

if (( ${#AVISOS[@]} )); then
  echo
  amar "════════ ${#AVISOS[@]} AVISO(S) QUE REVISAR ════════"
  for a in "${AVISOS[@]}"; do amar "  · $a"; done
fi
