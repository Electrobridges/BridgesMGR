# Capturas del panel

Van aquí, y desde aquí las enlaza el [README principal](../../README.md).

## ⚠️ Antes de subir ninguna

El repositorio es **público**. Una captura de un panel de administración
enseña más de lo que parece, y una vez publicada queda en el historial de git
aunque después se borre el archivo.

Repasa cada imagen buscando:

- **IPs reales** — la de la LAN en la barra del navegador, las IP reales de los
  clientes en la tabla de conexiones, la IP pública en *Configuración*.
- **Nombres de clientes VPN** — si son nombres de personas o de equipos de un
  cliente tuyo, no van.
- **Nombres de cuentas del panel** y a qué rol pertenecen.
- **Rutas del servidor** en *Configuración* y en *Logs*, que dibujan el mapa de
  la instalación.
- **El contenido del visor de logs**, que suele traer IPs y CN a puñados.

Lo más limpio es tomarlas de una instalación de pruebas con datos inventados,
no de una real con los nombres tapados: un recuadro negro encima sigue dejando
el texto si la imagen se recorta mal, y el nombre del archivo o los metadatos
pueden delatar el resto.

## Qué falta por capturar

| Archivo | Página | Qué debe verse |
|---|---|---|
| `panel.png` | `/` | La rejilla de cifras con datos plausibles, no todo a cero |
| `conexiones.png` | `/conexiones` | Dos o tres clientes conectados, con tráfico |
| `clientes.png` | `/clientes` | La tabla con un válido y un revocado, y el formulario de crear |
| `logs.png` | `/logs` | El visor con los cuatro niveles de color a la vista |
| `usuarios.png` | `/admin/usuarios` | Los tres roles, con el superusuario blindado |
| `login.png` | `/login` | La pantalla de entrada con los iconos de fondo y la firma |

## Cómo tomarlas

- **1440 px de ancho**, que es donde el diseño está pensado. Más ancho deja la
  tabla flotando; más estrecho activa el responsive y no representa el uso real.
- **PNG**, no JPG: hay texto pequeño y mucho contraste, y el JPG lo emborrona.
- Sin la barra del navegador, o con ella recortada si prefieres enseñar el
  candado del HTTPS — pero entonces tapa la IP.
- Si pesan más de ~500 KB, pásalas por un optimizador. El repo se clona en cada
  instalación.

## Al añadirlas

Enlázalas en el README principal, en la sección *Qué hace*. Con `alt` que
describa lo que se ve, no «captura de pantalla»: es lo que lee quien navega sin
imágenes o con lector de pantalla.
