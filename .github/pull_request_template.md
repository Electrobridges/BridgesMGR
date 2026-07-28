## Qué cambia

Breve descripción, y el porqué. Si cierra una incidencia: `Cierra #NN`.

## Tipo de cambio

- [ ] Corrección de error
- [ ] Funcionalidad nueva
- [ ] Documentación
- [ ] Refactor sin cambio de comportamiento
- [ ] Cambio incompatible

## Cómo lo has probado

```
pytest
```

Resultado:

## ¿Toca la mitad privilegiada?

`deploy/ovpn-web-helper`, `install.sh`, `ovpnweb.sudoers` o
`ovpn-web.service`.

- [ ] No lo toca
- [ ] Sí, y lo he probado en una VM Debian limpia. Qué probé y qué vi:

Si lo toca, confirma que sigue cumpliendo
[las cinco reglas](../docs/seguridad.md):

- [ ] El helper sigue sin aceptar rutas por argumento
- [ ] sudoers sigue autorizando solo el helper, sin comodines
- [ ] El regex de CN sigue idéntico a los dos lados
- [ ] `NoNewPrivileges` sigue en `false`
- [ ] Ningún `subprocess` con `shell=True`

## Repaso final

- [ ] `pytest` en verde
- [ ] Hay pruebas para el comportamiento nuevo o para el fallo corregido
- [ ] Textos, comentarios y commits en español
- [ ] Commits siguiendo Conventional Commits
- [ ] Documentación actualizada si hacía falta
- [ ] `CHANGELOG.md` actualizado en «Sin publicar»
- [ ] Ningún certificado, clave, `.ovpn`, `.db` ni `config.yaml` en el diff
