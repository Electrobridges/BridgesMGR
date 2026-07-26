#!/usr/bin/env bash
#
# Instalador de OpenVPN Manager Web para Debian/Ubuntu.
# Ejecutar como root DESDE la raíz del repo clonado:  sudo bash deploy/install.sh
#
# Es idempotente: puedes volver a lanzarlo para actualizar sin perder la base
# de datos ni la configuración.

set -euo pipefail

DESTINO=/opt/ovpn-web
CONFIG_DIR=/etc/ovpn-web
DATOS_DIR=/var/lib/ovpn-web
HELPER=/usr/local/sbin/ovpn-web-helper
USUARIO=ovpnweb
HTMX_VERSION=2.0.4
HTMX_URL="https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js"

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { rojo "Ejecuta como root"; exit 1; }
[[ -f app/main.py ]] || { rojo "Lanza el script desde la raíz del repo"; exit 1; }

# --------------------------------------------------------------- paquetes
info "Instalando dependencias del sistema"
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip python3-yaml openssl curl ca-certificates

# --------------------------------------------------------------- usuario
if ! id -u "$USUARIO" >/dev/null 2>&1; then
  info "Creando usuario de sistema '$USUARIO'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USUARIO"
fi

# Grupo 'adm' es el dueño de /var/log en Debian: así el panel lee los logs de
# OpenVPN sin pasar por el helper privilegiado.
info "Añadiendo '$USUARIO' al grupo adm (lectura de logs)"
usermod -aG adm "$USUARIO"

# --------------------------------------------------------------- archivos
info "Copiando la aplicación a $DESTINO"
mkdir -p "$DESTINO"
cp -r app "$DESTINO/"
cp requirements.txt "$DESTINO/"

info "Instalando el helper privilegiado en $HELPER"
install -o root -g root -m 0750 deploy/ovpn-web-helper "$HELPER"

# --------------------------------------------------------------- htmx
# El panel tiene una CSP estricta (script-src 'self'), así que HTMX se sirve
# desde local. Se verifica con confianza en el primer uso: la primera vez se
# guarda el hash, las siguientes se comprueba contra él. Si cambia, aborta.
info "Obteniendo HTMX $HTMX_VERSION"
TMP_HTMX=$(mktemp)
curl -fsSL "$HTMX_URL" -o "$TMP_HTMX"
HASH_ACTUAL=$(sha256sum "$TMP_HTMX" | cut -d' ' -f1)

if [[ -f deploy/htmx.sha256 ]]; then
  HASH_ESPERADO=$(cat deploy/htmx.sha256)
  if [[ "$HASH_ACTUAL" != "$HASH_ESPERADO" ]]; then
    rm -f "$TMP_HTMX"
    rojo "El hash de HTMX no coincide con deploy/htmx.sha256"
    rojo "  esperado: $HASH_ESPERADO"
    rojo "  obtenido: $HASH_ACTUAL"
    rojo "Revísalo antes de continuar."
    exit 1
  fi
  verde "Hash de HTMX verificado"
else
  echo "$HASH_ACTUAL" > deploy/htmx.sha256
  verde "Hash de HTMX guardado en deploy/htmx.sha256: $HASH_ACTUAL"
  echo "    Súbelo al repo para que las próximas instalaciones lo verifiquen."
fi

install -m 0644 "$TMP_HTMX" "$DESTINO/app/static/htmx.min.js"
rm -f "$TMP_HTMX"

# --------------------------------------------------------------- venv
info "Creando entorno virtual"
python3 -m venv "$DESTINO/venv"
"$DESTINO/venv/bin/pip" install --quiet --upgrade pip
"$DESTINO/venv/bin/pip" install --quiet -r "$DESTINO/requirements.txt"

# --------------------------------------------------------------- config
mkdir -p "$CONFIG_DIR/tls" "$DATOS_DIR"

if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  info "Instalando configuración de ejemplo"
  install -o root -g "$USUARIO" -m 0640 deploy/config.ejemplo.yaml "$CONFIG_DIR/config.yaml"
  CONFIG_NUEVA=1
else
  info "Conservando $CONFIG_DIR/config.yaml existente"
  chown root:"$USUARIO" "$CONFIG_DIR/config.yaml"
  chmod 0640 "$CONFIG_DIR/config.yaml"
  CONFIG_NUEVA=0
fi

# --------------------------------------------------------------- TLS
if [[ ! -f "$CONFIG_DIR/tls/cert.pem" ]]; then
  IP_LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
  IP_LAN=${IP_LAN:-127.0.0.1}
  info "Generando certificado autofirmado para $IP_LAN (10 años)"

  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CONFIG_DIR/tls/key.pem" \
    -out "$CONFIG_DIR/tls/cert.pem" \
    -subj "/CN=$IP_LAN/O=OpenVPN Manager Web" \
    -addext "subjectAltName=IP:$IP_LAN,IP:127.0.0.1" 2>/dev/null

  verde "Certificado creado. El navegador avisará de que es autofirmado: es esperado."
fi

chown -R root:"$USUARIO" "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR" "$CONFIG_DIR/tls"
chmod 0640 "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem"

chown -R "$USUARIO":"$USUARIO" "$DATOS_DIR"
chmod 0750 "$DATOS_DIR"
chown -R root:root "$DESTINO"

# --------------------------------------------------------------- sudoers
info "Instalando regla de sudo"
visudo -c -f deploy/ovpnweb.sudoers >/dev/null
install -o root -g root -m 0440 deploy/ovpnweb.sudoers /etc/sudoers.d/ovpnweb

# --------------------------------------------------------------- systemd
info "Instalando servicio systemd"
install -m 0644 deploy/ovpn-web.service /etc/systemd/system/ovpn-web.service
systemctl daemon-reload
systemctl enable ovpn-web >/dev/null

echo
verde "Instalación completada."
echo
if [[ "$CONFIG_NUEVA" == "1" ]]; then
  echo "SIGUIENTE PASO OBLIGATORIO — revisa la configuración:"
  echo "    nano $CONFIG_DIR/config.yaml"
  echo "  Ajusta al menos: servidor.host_bind, openvpn.status_path y"
  echo "  cliente_ovpn.remote_host."
  echo
fi
echo "Crea el primer administrador:"
echo "    cd $DESTINO && sudo -u $USUARIO venv/bin/python -m app.cli crear-usuario TU_USUARIO --rol admin"
echo
echo "Arranca el panel:"
echo "    systemctl start ovpn-web && systemctl status ovpn-web"
echo
echo "Y ábrelo en:  https://<IP_DEL_SERVIDOR>:55443"
