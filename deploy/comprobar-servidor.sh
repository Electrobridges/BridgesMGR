#!/usr/bin/env bash
#
# Comprueba que un servidor OpenVPN preexistente encaja con lo que el panel
# espera:  sudo bash deploy/comprobar-servidor.sh
#
# SOLO LEE. No instala, no escribe y no reinicia nada. Se puede lanzar en
# producción con clientes conectados.
#
# Existe porque instalar el panel sobre un OpenVPN que ya estaba montado es
# donde se va el tiempo: las rutas, los permisos y el nombre de la unidad
# difieren según quién montara la VPN, y varios de esos desajustes no dan la
# cara hasta que hace falta —revocar a alguien y que no surta efecto, o abrir
# la página de Logs y encontrarla vacía.
#
# Salida: 0 si no hay nada crítico, 1 si lo hay.

set -uo pipefail

CONFIG=${OVPN_WEB_CONFIG:-/etc/ovpn-web/config.yaml}
USUARIO_PANEL=ovpnweb

SERVER_CONF_ESTANDAR=(/etc/openvpn/server.conf /etc/openvpn/server/server.conf)

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

N_CRIT=0
N_AVISO=0

# Cada hallazgo lleva su arreglo. Un informe que dice qué está mal y no cómo
# se corrige obliga a buscarlo fuera, que es justo lo que este script evita.
critico() {
  rojo "  [CRÍTICO] $1"
  if [[ -n ${2:-} ]]; then printf '             %s\n' "$2"; fi
  N_CRIT=$((N_CRIT + 1))
}
aviso() {
  amar "  [AVISO]   $1"
  if [[ -n ${2:-} ]]; then printf '             %s\n' "$2"; fi
  N_AVISO=$((N_AVISO + 1))
}
bien() { verde "  [OK]      $1"; }

# ------------------------------------------------------------------ ayudas

# Lee una clave anidada del config.yaml. python3-yaml ya es dependencia del
# panel, así que no se añade nada por usarlo aquí.
cfgval() {
  python3 - "$CONFIG" "$1" <<'PY' 2>/dev/null || true
import sys, yaml
try:
    datos = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    sys.exit(0)
for clave in sys.argv[2].split("."):
    if not isinstance(datos, dict):
        sys.exit(0)
    datos = datos.get(clave)
    if datos is None:
        sys.exit(0)
print(datos)
PY
}

# Directiva de un server.conf, quedándose con la última aparición: es la que
# gana en OpenVPN.
directiva() {
  grep -E "^[[:space:]]*$1([[:space:]]|\$)" "$SERVER_CONF" 2>/dev/null \
    | tail -1 | sed -E "s|^[[:space:]]*$1[[:space:]]*||; s|[[:space:]]+\$||"
}

# Las rutas del server.conf pueden ser relativas. OpenVPN las resuelve contra
# su directorio de trabajo, que la unidad fija con --cd al del propio archivo.
# Sin esto se comprueba el archivo equivocado.
absoluta() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s/%s\n' "$(dirname "$SERVER_CONF")" "$1" ;;
  esac
}

# ¿Puede ese usuario leer de verdad ese archivo? Se intenta, no se deduce de
# los permisos: el directorio que lo contiene también tiene que dejarse
# atravesar, y ese detalle es el que se escapa mirando solo el modo del
# archivo.
puede_leer() {
  su -s /bin/sh "$1" -c "cat '$2' >/dev/null 2>&1" 2>/dev/null
}

# ------------------------------------------------------------------ arranque

if [[ $EUID -ne 0 ]]; then
  rojo "Ejecuta como root: sudo bash deploy/comprobar-servidor.sh"
  exit 2
fi

echo
info "Comprobando el servidor OpenVPN contra lo que espera el panel"
echo "    Configuración del panel: $CONFIG"
echo "    Solo lectura: no se modifica ni se reinicia nada."
echo

# ------------------------------------------------------- 1. el config.yaml

echo "Configuración del panel"
if [[ ! -f $CONFIG ]]; then
  critico "No existe $CONFIG" \
          "Instala el panel primero: sudo bash deploy/install.sh --sin-openvpn"
  echo
  echo "Sin la configuración del panel no se puede comparar nada. Se para aquí."
  exit 1
fi
bien "$CONFIG existe"

EASYRSA=$(cfgval openvpn.easyrsa_path); EASYRSA=${EASYRSA:-/etc/openvpn/easy-rsa}
SERVICIO_CFG=$(cfgval openvpn.servicio)
STATUS_CFG=$(cfgval openvpn.status_path)
LOG_CFG=$(cfgval openvpn.log_path)
MGMT_HOST_CFG=$(cfgval openvpn.mgmt_host)
MGMT_PORT_CFG=$(cfgval openvpn.mgmt_port)
CIPHER_CFG=$(cfgval cliente_ovpn.cipher)
SERVER_CONF_CFG=$(cfgval openvpn.server_conf)
echo

# ------------------------------------------------------- 2. el server.conf

echo "server.conf"
SERVER_CONF=""
for ruta in "$SERVER_CONF_CFG" "${SERVER_CONF_ESTANDAR[@]}"; do
  [[ -n $ruta && -f $ruta ]] && { SERVER_CONF=$ruta; break; }
done

if [[ -z $SERVER_CONF ]]; then
  critico "No se encuentra ningún server.conf" \
          "Buscado en: ${SERVER_CONF_ESTANDAR[*]}. Declara el tuyo en openvpn.server_conf"
  echo
  echo "Sin server.conf no se puede comprobar el resto. Se para aquí."
  exit 1
fi
bien "Encontrado en $SERVER_CONF"

# Aviso temprano: si las rutas son relativas, todo lo que sigue depende de
# resolverlas bien, y es de donde salen la mitad de las sorpresas.
if grep -qE '^[[:space:]]*(ca|cert|key|crl-verify|tls-crypt|tls-auth)[[:space:]]+[^/]' "$SERVER_CONF"; then
  aviso "Usa rutas relativas, que OpenVPN resuelve contra $(dirname "$SERVER_CONF")" \
        "No es un error, pero es de donde salen las confusiones: comprueba que apuntan a donde crees"
fi
echo

# ------------------------------------------------------- 3. la unidad activa

echo "Unidad de systemd"
UNIDAD_ACTIVA=$(systemctl list-units 'openvpn*' --state=running --no-legend --no-pager 2>/dev/null \
                | awk '{print $1}' | grep -E '^openvpn(-server)?@' | head -1)

if [[ -z $UNIDAD_ACTIVA ]]; then
  aviso "No hay ninguna unidad openvpn@* en marcha" \
        "Compruébalo con: systemctl list-units 'openvpn*' --all"
elif [[ $UNIDAD_ACTIVA == "${SERVICIO_CFG}.service" || $UNIDAD_ACTIVA == "$SERVICIO_CFG" ]]; then
  bien "$UNIDAD_ACTIVA, que es la que dice openvpn.servicio"
else
  critico "Corre '$UNIDAD_ACTIVA' pero el panel apunta a '$SERVICIO_CFG'" \
          "Las dos unidades leen archivos distintos y no son intercambiables. Corrige openvpn.servicio en $CONFIG"
fi
echo

# ------------------------------------------------------------- 4. la CRL

echo "Revocación (CRL)"
CRL_DIR=$(directiva crl-verify)
CRL_ESPERADA="$EASYRSA/pki/crl.pem"

if [[ -z $CRL_DIR ]]; then
  critico "El server.conf no tiene 'crl-verify'" \
          "Sin esa línea, revocar un certificado desde el panel NO impide que el cliente siga entrando"
else
  CRL_REAL=$(absoluta "$CRL_DIR")
  if [[ ! -f $CRL_REAL ]]; then
    critico "crl-verify apunta a $CRL_REAL, que no existe" \
            "OpenVPN no arrancará. Genera la CRL o corrige la ruta"
  elif [[ $(readlink -f "$CRL_REAL") != $(readlink -f "$CRL_ESPERADA") ]]; then
    critico "OpenVPN lee $CRL_REAL, pero el panel regenera $CRL_ESPERADA" \
            "Revocar desde el panel diría 'ok' y no surtiría efecto. Cambia crl-verify a la ruta del panel y reinicia"
  else
    bien "crl-verify apunta a la misma CRL que regenera el panel"
  fi

  # Caducada rechaza a TODOS, no solo a los revocados. Se mira antes que los
  # permisos porque el síntoma es idéntico y la causa, distinta.
  if [[ -f ${CRL_REAL:-} ]]; then
    if openssl crl -in "$CRL_REAL" -noout -nextupdate >/dev/null 2>&1; then
      FIN=$(openssl crl -in "$CRL_REAL" -noout -nextupdate | cut -d= -f2)
      if ! openssl crl -in "$CRL_REAL" -noout -checkend 0 >/dev/null 2>&1; then
        critico "La CRL caducó el $FIN" \
                "Una CRL vencida hace que OpenVPN rechace TODAS las conexiones. Regenérala"
      else
        bien "La CRL es válida hasta $FIN"
      fi
    fi
  fi
fi
echo

# ------------------------------- 5. quién es OpenVPN y si alcanza la CRL

echo "Permisos de la PKI"
USUARIO_VPN=$(directiva user)
USUARIO_VPN=${USUARIO_VPN:-root}

if [[ $USUARIO_VPN == root ]]; then
  bien "OpenVPN corre como root: no hay problema de acceso a la PKI"
else
  bien "OpenVPN suelta privilegios a '$USUARIO_VPN'"
  if [[ -n ${CRL_REAL:-} && -f ${CRL_REAL:-} ]]; then
    if puede_leer "$USUARIO_VPN" "$CRL_REAL"; then
      bien "'$USUARIO_VPN' puede leer la CRL"
    else
      critico "'$USUARIO_VPN' NO puede leer $CRL_REAL" \
              "Arregla con: chmod 0755 $EASYRSA $EASYRSA/pki && chmod 0644 $CRL_REAL"
    fi
  fi
fi

PRIV="$EASYRSA/pki/private"
if [[ -d $PRIV ]]; then
  MODO=$(stat -c '%a' "$PRIV")
  if [[ $MODO == 700 ]]; then
    bien "$PRIV en 0700"
  else
    critico "$PRIV en 0$MODO, debería ser 0700" \
            "Arregla con: chmod 0700 $PRIV"
  fi
else
  critico "No existe $PRIV" "¿Es correcto openvpn.easyrsa_path en $CONFIG?"
fi
echo

# --------------------------------------------------- 6. estado y management

echo "Lectura de conexiones"
STATUS_DIR=$(directiva status | awk '{print $1}')
if [[ -z $STATUS_DIR ]]; then
  aviso "El server.conf no tiene 'status'" "El panel se quedaría sin la vía de reserva para ver conexiones"
else
  STATUS_REAL=$(absoluta "$STATUS_DIR")
  if [[ $STATUS_REAL != "$STATUS_CFG" ]]; then
    aviso "OpenVPN escribe el estado en $STATUS_REAL y el panel lo busca en $STATUS_CFG" \
          "Corrige openvpn.status_path en $CONFIG"
  else
    bien "status_path coincide"
  fi
  if [[ -f $STATUS_REAL ]]; then
    if puede_leer "$USUARIO_PANEL" "$STATUS_REAL"; then
      bien "'$USUARIO_PANEL' puede leerlo"
    else
      aviso "'$USUARIO_PANEL' no puede leer $STATUS_REAL" \
            "Arregla con: chown root:adm $STATUS_REAL && chmod 0640 $STATUS_REAL"
    fi
  fi
fi

if [[ $(directiva status-version) == 3 ]]; then
  bien "status-version 3"
else
  aviso "Falta 'status-version 3'" "Es el formato que el panel lee mejor; con v1 pierde la IP real y la virtual por separado"
fi

MGMT=$(directiva management)
if [[ -z $MGMT ]]; then
  aviso "Sin 'management': el panel usará solo el archivo de estado" \
        "Añade: management 127.0.0.1 $MGMT_PORT_CFG"
else
  MGMT_H=$(echo "$MGMT" | awk '{print $1}')
  MGMT_P=$(echo "$MGMT" | awk '{print $2}')
  if [[ $MGMT_H == "$MGMT_HOST_CFG" && $MGMT_P == "$MGMT_PORT_CFG" ]]; then
    bien "management en $MGMT_H:$MGMT_P, como dice el panel"
  else
    aviso "management en $MGMT_H:$MGMT_P y el panel busca $MGMT_HOST_CFG:$MGMT_PORT_CFG" \
          "Corrige openvpn.mgmt_host y openvpn.mgmt_port en $CONFIG"
  fi
  [[ $MGMT_H == localhost ]] && aviso "'localhost' puede resolver a IPv6" \
      "El management de OpenVPN solo escucha en IPv4: pon 127.0.0.1 explícito"
fi
echo

# ------------------------------------------------------------- 7. los logs

echo "Logs"
LOG_DIR_DIR=$(directiva log-append); [[ -z $LOG_DIR_DIR ]] && LOG_DIR_DIR=$(directiva log)
if [[ -z $LOG_DIR_DIR ]]; then
  aviso "El server.conf no escribe log a ningún archivo" \
        "La página de Logs saldrá vacía. Añade: log-append $LOG_CFG (requiere reiniciar OpenVPN)"
else
  LOG_REAL=$(absoluta "$(echo "$LOG_DIR_DIR" | awk '{print $1}')")
  if [[ $LOG_REAL == "$LOG_CFG" ]]; then
    bien "log_path coincide"
  else
    aviso "OpenVPN escribe en $LOG_REAL y el panel lee $LOG_CFG" \
          "Corrige openvpn.log_path en $CONFIG"
  fi

  if [[ -f $LOG_REAL ]]; then
    if puede_leer "$USUARIO_PANEL" "$LOG_REAL"; then
      bien "'$USUARIO_PANEL' puede leer el log"
    else
      aviso "'$USUARIO_PANEL' no puede leer $LOG_REAL" \
            "Arregla con: chown root:adm $LOG_REAL && chmod 0640 $LOG_REAL"
    fi
  fi

  if grep -rqs -- "$(dirname "$LOG_REAL")" /etc/logrotate.d/; then
    bien "Hay logrotate para ese directorio"
  else
    aviso "Sin logrotate: $LOG_REAL crecerá sin límite" \
          "Añádelo con 'copytruncate': rotar renombrando exige avisar a OpenVPN con SIGHUP, que reinicia el túnel y desconecta a todos"
  fi
fi
echo

# ------------------------------------------------- 8. cifrado de los perfiles

echo "Perfiles .ovpn"
CIPHER_SRV=$(directiva cipher)
NCP=$(directiva ncp-ciphers); [[ -z $NCP ]] && NCP=$(directiva data-ciphers)

if [[ -n $CIPHER_SRV && -n $CIPHER_CFG && $CIPHER_SRV != "$CIPHER_CFG" ]]; then
  aviso "El servidor usa '$CIPHER_SRV' y los perfiles saldrán con '$CIPHER_CFG'" \
        "Corrige cliente_ovpn.cipher en $CONFIG"
elif [[ -n $CIPHER_SRV ]]; then
  bien "cipher coincide con el del servidor ($CIPHER_SRV)"
fi

if [[ -n $NCP && -n $CIPHER_CFG ]] && ! echo "$NCP" | grep -qF "$CIPHER_CFG"; then
  critico "El servidor solo negocia '$NCP' y los perfiles pedirán '$CIPHER_CFG'" \
          "Los clientes nuevos no conectarán. Corrige cliente_ovpn.cipher en $CONFIG"
fi

REMOTO=$(cfgval cliente_ovpn.remote_host)
if [[ -z $REMOTO || $REMOTO == vpn.ejemplo.com ]]; then
  critico "cliente_ovpn.remote_host sigue sin configurar ('$REMOTO')" \
          "Los .ovpn que emitas apuntarán a ninguna parte. Ponlo en $CONFIG"
else
  bien "remote_host: $REMOTO"
fi
echo

# ----------------------------------------------------- 9. CN del servidor

echo "Certificado del servidor"
CERT_SRV=$(directiva cert)
if [[ -n $CERT_SRV ]]; then
  CERT_REAL=$(absoluta "$CERT_SRV")
  if [[ -f $CERT_REAL ]]; then
    CN_SRV=$(openssl x509 -in "$CERT_REAL" -noout -subject 2>/dev/null \
             | sed -nE 's|.*CN[[:space:]]*=[[:space:]]*([^,/]+).*|\1|p' | sed 's/[[:space:]]*$//')
    if [[ -n $CN_SRV ]]; then
      bien "CN del servidor: $CN_SRV"
      case "${CN_SRV,,}" in
        server|ca) : ;;
        *) echo "             (no es 'server', así que el panel lo deduce de este archivo;"
           echo "              declara openvpn.server_conf si no lo encuentra solo)" ;;
      esac
    fi
  else
    aviso "El certificado del servidor no está en $CERT_REAL" "Revisa la directiva 'cert' de $SERVER_CONF"
  fi
fi
echo

# ------------------------------------------------------------------ resumen

echo "─────────────────────────────────────────────"
if [[ $N_CRIT -gt 0 ]]; then
  rojo "$N_CRIT crítico(s) y $N_AVISO aviso(s)."
  echo
  echo "Los críticos hay que resolverlos: son los que hacen que algo parezca"
  echo "funcionar sin funcionar —revocar sin efecto, o la VPN rechazando a todos."
  exit 1
elif [[ $N_AVISO -gt 0 ]]; then
  amar "Sin críticos, $N_AVISO aviso(s)."
  echo
  echo "El panel funcionará; los avisos son funciones que se quedarán a medias."
  exit 0
else
  verde "Todo encaja."
  exit 0
fi
