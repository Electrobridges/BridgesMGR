#!/usr/bin/env bash
#
# Deja el log de OpenVPN con marca de tiempo en cada línea.
#
# Las distribuciones arrancan OpenVPN con '--suppress-timestamps' desde la
# unidad que empaquetan —viene de la unidad que publica el propio OpenVPN, así
# que está igual en Debian, Ubuntu y Arch—, y entonces NINGUNA línea del log
# lleva fecha. El panel reconoce los sucesos igual, pero sin el cuándo no puede
# restar: la columna de duración de la vista de sesiones se queda vacía.
#
# Esa bandera no se quita desde el server.conf porque no existe la opción
# contraria. La única vía es repetir el ExecStart de la unidad sin ella.
#
# Vive aparte porque lo necesitan los dos instaladores y una sola copia no se
# desincroniza: instalar-openvpn.sh al montar la VPN, e install.sh en cada
# actualización, que es lo único que alcanza a un servidor ya instalado.
#
# Uso:  bash fechas-log.sh [UNIDAD] [--reiniciar]
#
#   UNIDAD        la unidad de OpenVPN; si no se da, se busca la que corra
#   --reiniciar   reiniciar OpenVPN para que surta efecto ahora mismo
#
# Sin --reiniciar el añadido queda escrito pero inerte hasta el siguiente
# arranque de OpenVPN. Reiniciar DESCONECTA a todos los clientes conectados,
# así que quien llama decide, y aquí solo se reinicia si de verdad se ha
# cambiado algo: repetir el script no vuelve a cortar a nadie.

set -euo pipefail

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

UNIDAD=""
REINICIAR=0
for arg in "$@"; do
  case "$arg" in
    --reiniciar) REINICIAR=1 ;;
    -*) rojo "Opción desconocida: $arg"; exit 2 ;;
    *)  UNIDAD="$arg" ;;
  esac
done

# Sin unidad, la que esté corriendo. El mismo patrón que comprobar-servidor.sh,
# porque hay dos nombres en circulación: 'openvpn@server' en instalaciones
# antiguas y 'openvpn-server@server' en las de ahora.
if [[ -z $UNIDAD ]]; then
  UNIDAD=$(systemctl list-units 'openvpn*' --state=running --no-legend --no-pager 2>/dev/null \
           | awk '{print $1}' | grep -E '^openvpn(-server)?@' | head -1 || true)
fi

if [[ -z $UNIDAD ]]; then
  amar "No hay ninguna unidad de OpenVPN en marcha: no se toca nada."
  exit 0
fi

EXEC_ACTUAL=$(systemctl show "$UNIDAD" -p ExecStart --value 2>/dev/null \
              | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | sed 's/[[:space:]]*$//')

if [[ -z $EXEC_ACTUAL ]]; then
  amar "No se pudo leer el ExecStart de $UNIDAD: no se toca nada."
  exit 0
fi

if [[ $EXEC_ACTUAL != *--suppress-timestamps* ]]; then
  verde "El log de OpenVPN ya lleva fecha ($UNIDAD)."
  exit 0
fi

# El ExecStart se copia del que ya hay en vez de escribirlo a mano: si una
# actualización de OpenVPN cambia sus argumentos, el añadido los recoge en
# lugar de congelar los de hoy.
#
# Va a la unidad CONCRETA y no a la plantilla porque systemd devuelve %t y %i
# ya resueltos; escritos en la plantilla valdrían para esta instancia y
# romperían cualquier otra.
UNIDAD_BASE="${UNIDAD%.service}"
DROPIN_DIR="/etc/systemd/system/${UNIDAD_BASE}.service.d"
DROPIN="$DROPIN_DIR/fechas.conf"

info "Quitando '--suppress-timestamps' de $UNIDAD_BASE"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<FIN
# Escrito por deploy/fechas-log.sh. Sin fecha en el log, el panel no puede
# calcular cuánto duró cada sesión. El ExecStart se repite entero porque
# systemd exige vaciarlo antes de volver a ponerlo.
[Service]
ExecStart=
ExecStart=${EXEC_ACTUAL// --suppress-timestamps/}
FIN
systemctl daemon-reload
verde "Añadido escrito en $DROPIN"

if [[ "$REINICIAR" != "1" ]]; then
  amar "Queda inerte hasta que OpenVPN reinicie. Cuando puedas:"
  echo "    systemctl restart $UNIDAD_BASE"
  echo "  (reiniciar desconecta a los clientes conectados)"
  exit 0
fi

# Se dice a cuánta gente va a cortar antes de hacerlo. El archivo de estado
# sale del propio ExecStart, así que no hay que adivinar dónde está.
STATUS=$(echo "$EXEC_ACTUAL" | sed -n 's/.*--status \([^ ]*\).*/\1/p')
if [[ -n $STATUS && -r $STATUS ]]; then
  CONECTADOS=$(grep -c '^CLIENT_LIST' "$STATUS" 2>/dev/null || echo 0)
  if [[ "$CONECTADOS" -gt 0 ]]; then
    amar "Reiniciando OpenVPN: se desconectan $CONECTADOS cliente(s)."
  fi
fi

info "Reiniciando $UNIDAD_BASE"
systemctl restart "$UNIDAD_BASE"
sleep 2

if systemctl is-active --quiet "$UNIDAD_BASE"; then
  verde "OpenVPN en marcha y el log ya lleva fecha."
else
  rojo "OpenVPN no ha vuelto a arrancar. Mira qué dice:"
  echo "    journalctl -u $UNIDAD_BASE -n 40 --no-pager"
  exit 1
fi
