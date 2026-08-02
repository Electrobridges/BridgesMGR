#!/usr/bin/env bash
#
# Reconstruye la autoridad certificadora desde cero:
#   sudo bash deploy/reconstruir-ca.sh
#
# CUÁNDO HACE FALTA, que no es cuando parece. Si se filtra el .ovpn o la clave
# de UN CLIENTE, lo que toca es revocarlo: para eso está la CRL. Esto es para
# cuando se filtra la clave privada de la CA —quien la tenga puede firmar
# certificados nuevos, con serials que no figuran en ninguna CRL, así que
# revocar no sirve de nada— o para borrar de verdad el pasado de una PKI
# heredada.
#
# POR QUÉ NO ESTÁ EN EL PANEL NI EN EL HELPER. La regla de sudo autoriza el
# binario del helper entero, no sus subcomandos: un séptimo subcomando aquí
# sería invocable por un panel comprometido, que es justo el escenario que
# motiva esta función. Este script NO está en /etc/sudoers.d/ovpnweb, así que
# el proceso del panel no lo alcanza. Lo lanza una persona con sudo.
#
# DEJA A TODOS FUERA. Los certificados viejos quedan firmados por una CA que ya
# no existe: ningún .ovpn anterior vuelve a servir. Hay que repartir perfiles
# nuevos a todo el mundo.

set -uo pipefail

CONFIG=${OVPN_WEB_CONFIG:-/etc/ovpn-web/config.yaml}
DESTINO=/opt/ovpn-web
USUARIO_PANEL=ovpnweb
RESPALDOS=/var/backups/ovpn-web

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
morir() { rojo "$*"; exit 1; }

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

directiva() {
  grep -E "^[[:space:]]*$1([[:space:]]|\$)" "$SERVER_CONF" 2>/dev/null \
    | tail -1 | sed -E "s|^[[:space:]]*$1[[:space:]]*||; s|[[:space:]]+\$||"
}

# Las rutas del server.conf pueden ser relativas: OpenVPN las resuelve contra
# su directorio de trabajo, que es el del propio archivo.
absoluta() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s/%s\n' "$(dirname "$SERVER_CONF")" "$1" ;;
  esac
}

[[ $EUID -eq 0 ]] || morir "Ejecuta como root: sudo bash deploy/reconstruir-ca.sh"
[[ -f $CONFIG ]] || morir "No existe $CONFIG"

EASYRSA=$(cfgval openvpn.easyrsa_path); EASYRSA=${EASYRSA:-/etc/openvpn/easy-rsa}
SERVICIO=$(cfgval openvpn.servicio);    SERVICIO=${SERVICIO:-openvpn@server}
SERVER_CONF=$(cfgval openvpn.server_conf)

if [[ -z $SERVER_CONF || ! -f $SERVER_CONF ]]; then
  for r in /etc/openvpn/server.conf /etc/openvpn/server/server.conf; do
    [[ -f $r ]] && { SERVER_CONF=$r; break; }
  done
fi

[[ -n ${SERVER_CONF:-} && -f $SERVER_CONF ]] || morir "No se encuentra el server.conf"
[[ -x $EASYRSA/easyrsa ]] || morir "No se encuentra easyrsa en $EASYRSA"

PKI="$EASYRSA/pki"

# ------------------------------------------------------- qué hay ahora mismo

CA_ACTUAL="(sin CA)"
[[ -f $PKI/ca.crt ]] && CA_ACTUAL=$(openssl x509 -in "$PKI/ca.crt" -noout -subject 2>/dev/null \
  | sed -nE 's|.*CN[[:space:]]*=[[:space:]]*([^,/]+).*|\1|p' | sed 's/[[:space:]]*$//')

CERT_SRV=$(absoluta "$(directiva cert)")
CN_SERVIDOR=""
[[ -f $CERT_SRV ]] && CN_SERVIDOR=$(openssl x509 -in "$CERT_SRV" -noout -subject 2>/dev/null \
  | sed -nE 's|.*CN[[:space:]]*=[[:space:]]*([^,/]+).*|\1|p' | sed 's/[[:space:]]*$//')

[[ -n $CN_SERVIDOR ]] || morir "No se pudo leer el CN del certificado de servidor ($CERT_SRV)"

# Clientes válidos: los de issued/ menos el del propio servidor
CLIENTES=()
if [[ -d $PKI/issued ]]; then
  while IFS= read -r f; do
    cn=$(basename "$f" .crt)
    [[ $cn == "$CN_SERVIDOR" ]] && continue
    CLIENTES+=("$cn")
  done < <(find "$PKI/issued" -maxdepth 1 -name '*.crt' | sort)
fi

# Los que referencia el server.conf y NO viven dentro de la PKI: son copias y
# hay que refrescarlas, o OpenVPN seguiría cargando la CA vieja. Es el paso que
# no se puede adivinar, y el que deja la VPN caída si se olvida.
COPIAS=()
for d in ca cert key; do
  ruta=$(absoluta "$(directiva $d)")
  [[ -n $ruta && $ruta != "$PKI"/* ]] && COPIAS+=("$d:$ruta")
done

# ------------------------------------------------------------- el destrozo

echo
amar "════════ RECONSTRUIR LA AUTORIDAD CERTIFICADORA ════════"
echo
echo "  CA actual:            $CA_ACTUAL"
echo "  Certificado servidor: $CN_SERVIDOR  (se conserva el nombre)"
echo "  PKI:                  $PKI"
echo "  server.conf:          $SERVER_CONF"
echo "  Servicio:             $SERVICIO"
echo
if [[ ${#CLIENTES[@]} -gt 0 ]]; then
  echo "  Clientes con certificado ahora (${#CLIENTES[@]}):"
  printf '    · %s\n' "${CLIENTES[@]}"
else
  echo "  No hay ningún certificado de cliente."
fi
echo
if [[ ${#COPIAS[@]} -gt 0 ]]; then
  echo "  El server.conf apunta a copias fuera de la PKI; se refrescarán:"
  for c in "${COPIAS[@]}"; do echo "    · ${c#*:}"; done
else
  echo "  El server.conf apunta directo a la PKI: nada que recolocar."
fi
echo
rojo "  TODOS los .ovpn repartidos dejarán de funcionar, sin excepción."
rojo "  Los certificados actuales quedan firmados por una CA que ya no existe."
echo "  La CRL empieza de cero, y es correcto: no hay nada que bloquear."
echo

printf 'Escribe RECONSTRUIR para continuar, cualquier otra cosa para salir: '
read -r respuesta
[[ $respuesta == "RECONSTRUIR" ]] || { echo "Cancelado. No se ha tocado nada."; exit 0; }

REEMITIR=no
if [[ ${#CLIENTES[@]} -gt 0 ]]; then
  echo
  echo "¿Reemitir certificado para esos ${#CLIENTES[@]} cliente(s) con la CA nueva?"
  echo "  Saldrán SIN contraseña: no hay forma de saber cuál tenía cada uno."
  echo "  Si dices que no, la PKI queda solo con la CA y el servidor, y los"
  echo "  clientes se crean después uno a uno desde el panel."
  printf '  [s/N]: '
  read -r r
  [[ $r =~ ^[sS]$ ]] && REEMITIR=si
fi

# --------------------------------------------------------------- respaldo

SELLO=$(date +%Y%m%d-%H%M%S)
COPIA="$RESPALDOS/ca-$SELLO"
info "Respaldando en $COPIA"
mkdir -p "$COPIA" || morir "No se pudo crear $COPIA"
chmod 0700 "$RESPALDOS" "$COPIA"

cp -a "$PKI" "$COPIA/pki" || morir "No se pudo respaldar la PKI. Se aborta sin tocar nada."
cp -a "$SERVER_CONF" "$COPIA/" || morir "No se pudo respaldar el server.conf"
for c in "${COPIAS[@]}"; do
  cp -a "${c#*:}" "$COPIA/" 2>/dev/null
done
verde "Respaldo hecho. Vuelta atrás: cp -a $COPIA/pki $PKI && systemctl restart $SERVICIO"

restaurar() {
  rojo "Restaurando el respaldo…"
  rm -rf "$PKI"
  cp -a "$COPIA/pki" "$PKI"
  cp -a "$COPIA/$(basename "$SERVER_CONF")" "$SERVER_CONF"
  for c in "${COPIAS[@]}"; do
    cp -a "$COPIA/$(basename "${c#*:}")" "${c#*:}" 2>/dev/null
  done
  systemctl restart "$SERVICIO"
  sleep 2
  if systemctl is-active --quiet "$SERVICIO"; then
    amar "Restaurado. La VPN vuelve a estar como antes."
  else
    rojo "LA RESTAURACIÓN TAMBIÉN FALLÓ. El respaldo está intacto en $COPIA"
  fi
}

# ------------------------------------------------------------ la PKI nueva

cd "$EASYRSA" || morir "No se pudo entrar en $EASYRSA"

info "Creando la PKI nueva (respeta el vars actual: algoritmo y curva)"
./easyrsa --batch init-pki >/dev/null || { restaurar; morir "init-pki falló"; }
./easyrsa --batch --req-cn="OpenVPN Manager Web CA" build-ca nopass >/dev/null \
  || { restaurar; morir "build-ca falló"; }

info "Emitiendo el certificado de servidor '$CN_SERVIDOR'"
./easyrsa --batch build-server-full "$CN_SERVIDOR" nopass >/dev/null \
  || { restaurar; morir "No se pudo emitir el certificado de servidor"; }

./easyrsa --batch gen-crl >/dev/null || { restaurar; morir "gen-crl falló"; }

# Los mismos permisos que deja instalar-openvpn.sh: OpenVPN suelta privilegios
# a 'nobody' y tiene que poder atravesar pki/ y leer la CRL.
chmod 0755 "$EASYRSA" "$PKI"
chmod 0700 "$PKI/private"
chmod 0644 "$PKI/crl.pem"

if [[ $REEMITIR == si ]]; then
  info "Reemitiendo ${#CLIENTES[@]} cliente(s)"
  for cn in "${CLIENTES[@]}"; do
    if ./easyrsa --batch build-client-full "$cn" nopass >/dev/null; then
      echo "    · $cn"
    else
      amar "    · $cn — FALLÓ, créalo a mano desde el panel"
    fi
  done
fi

# ------------------------------------------------ recolocar lo que se usa

for c in "${COPIAS[@]}"; do
  cual=${c%%:*}; ruta=${c#*:}
  case $cual in
    ca)   origen="$PKI/ca.crt" ;;
    cert) origen="$PKI/issued/$CN_SERVIDOR.crt" ;;
    key)  origen="$PKI/private/$CN_SERVIDOR.key" ;;
  esac
  info "Refrescando $ruta"
  cp "$origen" "$ruta" || { restaurar; morir "No se pudo refrescar $ruta"; }
done

# --------------------------------------------------------------- reiniciar

info "Reiniciando $SERVICIO"
systemctl restart "$SERVICIO"
sleep 3

if ! systemctl is-active --quiet "$SERVICIO"; then
  rojo "$SERVICIO no ha vuelto a levantar."
  restaurar
  morir "Se ha deshecho el cambio. Revisa: journalctl -u $SERVICIO -n 40"
fi

verde "$SERVICIO activo con la CA nueva."

# ------------------------------------------------- avisar al panel

if [[ $REEMITIR == si && ${#CLIENTES[@]} -gt 0 && -x $DESTINO/venv/bin/python ]]; then
  # Como ovpnweb y no como root: si root escribiera la base, SQLite dejaría
  # archivos -wal y -shm suyos y las escrituras del panel fallarían después.
  sudo -u "$USUARIO_PANEL" "$DESTINO/venv/bin/python" -m app.cli marcar-reparto \
    reconstruccion_ca "${CLIENTES[@]}" \
    --detalle "CA reconstruida el $SELLO. Respaldo en $COPIA" \
    2>/dev/null && verde "Aviso de reparto anotado en el panel."
fi

echo
verde "════════ HECHO ════════"
echo
echo "  CA nueva emitida y en uso. Respaldo: $COPIA"
echo
if [[ $REEMITIR == si ]]; then
  echo "  Descarga los .ovpn desde el panel y repártelos: ninguno de los"
  echo "  anteriores sirve ya."
else
  echo "  No hay clientes. Créalos desde el panel."
fi
echo
amar "  Si el disparo fue una clave de CA filtrada, reconstruirla no basta:"
amar "  averigua cómo salió, o volverá a salir."
