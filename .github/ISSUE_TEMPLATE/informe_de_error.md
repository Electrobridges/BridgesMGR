---
name: Informe de error
about: Algo no funciona como debería
title: ''
labels: error
assignees: ''
---

> **Antes de pegar nada**: no incluyas certificados, claves, archivos `.ovpn`
> ni tu `config.yaml` completo. Sustituye las direcciones reales por ejemplos.

## Qué pasa

Descripción breve del problema.

## Cómo reproducirlo

1.
2.
3.

## Qué esperabas que pasara

## Qué pasó en realidad

Pega el aviso que salió en pantalla, si lo hubo.

## Entorno

- Distribución y versión:
- Versión de OpenVPN (`openvpn --version | head -1`):
- Versión de Python (`python3 --version`):
- Versión o commit del panel:
- Navegador:

## Registro del servicio

```
sudo journalctl -u ovpn-web -n 50 --no-pager
```

```
(pega aquí la salida)
```

## Si es un problema con la PKI

Salida de probar el helper a mano, tal como lo llama el panel:

```
sudo -u ovpnweb sudo -n /usr/local/sbin/ovpn-web-helper listar
```

```
(pega aquí la salida)
```

## Configuración relevante

Solo las claves que tengan que ver, con los valores reales sustituidos:

```yaml
openvpn:
  status_path: "..."
  mgmt_host: "127.0.0.1"
```
