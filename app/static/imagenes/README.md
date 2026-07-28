# Imágenes de marca

Isotipo de **BridgesMGR** —escudo con llave— en sus dos variantes. Se sirven
desde `/static/imagenes/`.

| Archivo | Qué es | Dónde se usa |
|---|---|---|
| `bridgesmgr-oscuro-transparente.png` | 960×960, escudo cian con llave blanca | Barra superior, login y favicon |
| `bridgesmgr-claro-transparente.png` | 960×960, escudo navy con llave cian | Fondos claros: documentación, impresión |
| `BridgesMGR Logo-selection-oscuro.png` | 192×192, con fondo navy | Sin usar |
| `BridgesMGR Logo-selection-claro.png` | 484×484, con fondo blanco | Sin usar |

El nombre se compone en la propia página, no va en la imagen: *Bridges* en
blanco y *MGR* en Cian Marca (`#10c4d8`), Poppins ExtraBold. Lo hace la regla
`.marca strong span` de `estilo.css`, según [DESIGN.md](../../../DESIGN.md).

## Por qué la variante oscura también vale de favicon

El escudo es cian opaco y la llave recorta en blanco **sobre** el escudo, así
que se lee igual en una pestaña clara que en una oscura. Por eso el fondo
transparente no da problemas aquí.

## Si añades o cambias archivos

- **Nada de referencias externas** dentro de un SVG (`<image>`, `xlink:href`,
  `@import`): la CSP del panel es `'self'` y las bloquea; el logo saldría roto.
- En los SVG, **convierte el texto a contornos**. Un `<text>` con
  `font-family: Poppins` se ve bien dentro de la página, pero dentro de un
  `<img>` o de un favicon la fuente no está cargada y cae a la del sistema.
- Si cambias un nombre de archivo, hay que tocar también `base.html`,
  `login.html` y `login_totp.html`.

## Pendiente si algún día importa

No hay iconos recortados a 32/180/512 px ni `apple-touch-icon`: el navegador
reduce el PNG de 960 px, que para un panel de LAN va sobrado. Solo haría falta
si se quisiera instalar como aplicación en el escritorio o en un móvil.
