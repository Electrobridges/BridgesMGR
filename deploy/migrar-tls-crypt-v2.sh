#!/usr/bin/env bash
#
# Pasa el servidor de tls-crypt (una clave compartida) a tls-crypt-v2 (una
# clave por perfil):
#   sudo bash deploy/migrar-tls-crypt-v2.sh
#
# POR QUÉ. Con tls-crypt, la clave que protege el canal de control va igual en
# todos los .ovpn: quien se haga con uno tiene la de todos, y la única salida
# es rotarla y repartir perfiles nuevos a todo el mundo. Con tls-crypt-v2 cada
# perfil lleva una clave propia, envuelta con la del servidor, y el panel
# genera una nueva en cada descarga.
#
# POR QUÉ NO ESTÁ EN EL PANEL NI EN EL HELPER. Hay que cambiar el server.conf,
# y quien pueda escribirlo mete un 'script-security 2' con un 'up' propio y
# ejecuta código como root. Como reconstruir-ca.sh, esto lo lanza una persona
# con sudo y no está en /etc/sudoers.d/ovpnweb.
#
# DEJA A TODOS FUERA hasta que reciban un perfil nuevo, y exige clientes
# OpenVPN 2.6 o posteriores: los 2.5 no saben qué es tls-crypt-v2.

set -uo pipefail

CONFIG=${OVPN_WEB_CONFIG:-/etc/ovpn-web/config.yaml}
DESTINO=/opt/ovpn-web
USUARIO_PANEL=ovpnweb
HELPER=/usr/local/sbin/ovpn-web-helper
RESPALDOS=/var/backups/ovpn-web
CLAVE_V2=/etc/openvpn/tls-crypt-v2-server.key

# CVE-2025-2704: de 2.6.1 a 2.6.13, un servidor con tls-crypt-v2 se puede
# tumbar con paquetes manipulados. No se activa por debajo del arreglo.
VERSION_MINIMA=2.6.14

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

[[ $EUID -eq 0 ]] || morir "Ejecuta como root: sudo bash deploy/migrar-tls-crypt-v2.sh"
[[ -f $CONFIG ]] || morir "No existe $CONFIG"

SERVICIO=$(cfgval openvpn.servicio); SERVICIO=${SERVICIO:-openvpn@server}
SERVER_CONF=$(cfgval openvpn.server_conf)
if [[ -z $SERVER_CONF || ! -f $SERVER_CONF ]]; then
  for r in /etc/openvpn/server.conf /etc/openvpn/server/server.conf; do
    [[ -f $r ]] && { SERVER_CONF=$r; break; }
  done
fi
[[ -n ${SERVER_CONF:-} && -f $SERVER_CONF ]] || morir "No se encuentra el server.conf"

if grep -qE '^[[:space:]]*tls-crypt-v2[[:space:]]' "$SERVER_CONF"; then
  verde "El server.conf ya usa tls-crypt-v2. Nada que hacer."
  exit 0
fi

# Una clave en línea (<tls-crypt>…</tls-crypt>) no se sabe sustituir sin
# riesgo de dejar el archivo a medias: se pide hacerlo a mano.
if grep -qE '^[[:space:]]*<(tls-crypt|tls-auth)>' "$SERVER_CONF"; then
  morir "El server.conf lleva la clave en línea (<tls-crypt>). Pásala a un archivo y repite."
fi

VERSION=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
[[ -n $VERSION ]] || morir "No se pudo averiguar la versión de OpenVPN"
if [[ $(printf '%s\n%s\n' "$VERSION_MINIMA" "$VERSION" | sort -V | head -1) != "$VERSION_MINIMA" ]]; then
  morir "OpenVPN $VERSION: hace falta $VERSION_MINIMA o posterior (CVE-2025-2704). Actualiza OpenVPN y repite."
fi

echo
amar "════════ MIGRAR A TLS-CRYPT-V2 ════════"
echo
echo "  Servidor:   $SERVER_CONF (OpenVPN $VERSION)"
echo "  Clave nueva: $CLAVE_V2"
echo
echo "  · Ningún .ovpn repartido hasta hoy volverá a conectar."
echo "  · Los clientes tienen que ser OpenVPN 2.6 o posteriores"
echo "    (OpenVPN Connect 3.x, el cliente de Windows 2.6, NetworkManager reciente)."
echo "  · Se hace copia de server.conf y config.yaml, y si OpenVPN no vuelve a"
echo "    levantar se deshace todo solo."
echo
printf 'Escribe MIGRAR para continuar, cualquier otra cosa para salir: '
read -r respuesta
[[ $respuesta == "MIGRAR" ]] || { echo "Cancelado. No se ha tocado nada."; exit 0; }

# --------------------------------------------------------------- respaldo
SELLO=$(date +%Y%m%d-%H%M%S)
COPIA="$RESPALDOS/tls-crypt-v2-$SELLO"
mkdir -p "$COPIA" && chmod 0700 "$RESPALDOS" "$COPIA" || morir "No se pudo crear $COPIA"
cp -a "$SERVER_CONF" "$COPIA/" || morir "No se pudo respaldar el server.conf"
cp -a "$CONFIG" "$COPIA/" || morir "No se pudo respaldar $CONFIG"
verde "Respaldo en $COPIA"

restaurar() {
  rojo "Deshaciendo…"
  cp -a "$COPIA/$(basename "$SERVER_CONF")" "$SERVER_CONF"
  cp -a "$COPIA/$(basename "$CONFIG")" "$CONFIG"
  systemctl restart "$SERVICIO"
  sleep 2
  if systemctl is-active --quiet "$SERVICIO"; then
    amar "Deshecho. La VPN vuelve a estar como antes."
  else
    rojo "LA VUELTA ATRÁS TAMBIÉN FALLÓ. Los originales están en $COPIA"
  fi
}

# --------------------------------------------------------------- clave
if [[ ! -f $CLAVE_V2 ]]; then
  info "Generando la clave de servidor"
  openvpn --genkey tls-crypt-v2-server "$CLAVE_V2" || morir "No se pudo generar $CLAVE_V2"
fi
chown root:root "$CLAVE_V2"
chmod 0600 "$CLAVE_V2"

# Los clientes que hay ahora, para el aviso de reparto del panel. Se pregunta
# antes de tocar nada: si el helper no responde, mejor saberlo ya.
CLIENTES=$("$HELPER" listar 2>/dev/null | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["validos"]))' 2>/dev/null || true)

# --------------------------------------------------------------- server.conf
info "Cambiando el server.conf"
# Python y no sed: hay que comentar una o dos líneas y escribir una sola en su
# lugar, y en sed la alternancia de la expresión choca con los delimitadores.
# La línea vieja se queda comentada donde estaba, para que se vea qué había.
python3 - "$SERVER_CONF" "$CLAVE_V2" <<'PY' || { restaurar; morir "No se pudo editar el server.conf"; }
import re, sys
ruta, clave = sys.argv[1], sys.argv[2]
lineas = open(ruta, encoding="utf-8").read().splitlines()
salida, puesta = [], False
for linea in lineas:
    if re.match(r'^\s*(tls-crypt|tls-auth)\s', linea):
        salida.append("# %s  (antes de tls-crypt-v2)" % linea.strip())
        if not puesta:
            salida.append("tls-crypt-v2 %s" % clave)
            puesta = True
    else:
        salida.append(linea)
if not puesta:
    salida += ["", "tls-crypt-v2 %s" % clave]
open(ruta, "w", encoding="utf-8").write("\n".join(salida) + "\n")
PY
chown root:root "$SERVER_CONF"
chmod 0600 "$SERVER_CONF"

# --------------------------------------------------------------- config.yaml
info "Anotando la clave en $CONFIG"
if grep -qE '^[[:space:]]+tls_crypt_v2:' "$CONFIG"; then
  sed -i -E "s|^([[:space:]]+tls_crypt_v2:).*|\\1 \"${CLAVE_V2}\"|" "$CONFIG"
else
  sed -i -E "s|^([[:space:]]+)(tls_crypt:.*)$|\\1\\2\\n\\1tls_crypt_v2: \"${CLAVE_V2}\"|" "$CONFIG"
fi
grep -qE "^[[:space:]]+tls_crypt_v2: \"${CLAVE_V2}\"" "$CONFIG" \
  || { restaurar; morir "No se pudo anotar tls_crypt_v2 en $CONFIG"; }

# --------------------------------------------------------------- reiniciar
info "Reiniciando $SERVICIO"
systemctl restart "$SERVICIO"
sleep 3
if ! systemctl is-active --quiet "$SERVICIO"; then
  rojo "$SERVICIO no ha vuelto a levantar."
  restaurar
  morir "Revisa: journalctl -u $SERVICIO -n 40"
fi
verde "$SERVICIO activo con tls-crypt-v2."

# El panel valida config.yaml al arrancar: se reinicia para que lea la clave.
systemctl is-active --quiet ovpn-web && systemctl restart ovpn-web

# --------------------------------------------------------------- avisar al panel
if [[ -n $CLIENTES && -x $DESTINO/venv/bin/python ]]; then
  # Como ovpnweb y no como root, por los -wal y -shm de SQLite.
  # shellcheck disable=SC2086
  (cd "$DESTINO" && sudo -u "$USUARIO_PANEL" venv/bin/python -m app.cli marcar-reparto \
    migracion_tls_crypt_v2 $CLIENTES \
    --detalle "Migrado a tls-crypt-v2 el $SELLO. Respaldo en $COPIA") \
    2>/dev/null && verde "Aviso de reparto anotado en el panel."
fi

echo
verde "════════ HECHO ════════"
echo
echo "  Descarga los .ovpn desde el panel y repártelos: cada uno lleva ya su"
echo "  propia clave. Vuelta atrás: cp $COPIA/* a su sitio y reinicia $SERVICIO."
