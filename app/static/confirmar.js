/* Sustituye el confirm() del navegador por un diálogo del propio panel.
 *
 * Archivo aparte servido desde /static, nunca en línea: la CSP es
 * script-src 'self', que admite archivos locales y prohíbe los inline y los
 * remotos. Es la misma vía por la que se sirve htmx.min.js.
 *
 * Se engancha al evento htmx:confirm, así que cubre los hx-confirm que ya hay
 * repartidos por las plantillas sin tocar ninguna: revocar, restaurar,
 * eliminar, desconectar, borrar una cuenta y demás.
 *
 * Ojo con la degradación, que aquí importa más de lo normal: si este archivo
 * no llegara a cargar, HTMX vuelve a su window.confirm nativo. La guarda de
 * las acciones destructivas NO depende de que esto funcione; solo su aspecto.
 */
(function () {
  "use strict";

  document.addEventListener("htmx:confirm", function (evt) {
    var pregunta = evt.detail.question;

    // Sin hx-confirm no hay nada que confirmar: HTMX dispara este evento en
    // toda petición, y quedárselo aquí las bloquearía todas.
    if (!pregunta) {
      return;
    }

    var dialogo = document.getElementById("dialogo-confirmar");

    // <dialog> sin showModal es un navegador que no lo soporta. Se deja pasar
    // para que actúe el confirm nativo en vez de quedarse sin confirmación.
    if (!dialogo || typeof dialogo.showModal !== "function") {
      return;
    }

    evt.preventDefault();

    dialogo.querySelector(".dialogo-texto").textContent = pregunta;

    // El botón hereda el tono del que lo disparó: lo destructivo se confirma
    // con un botón que también lo parece.
    var origen = evt.detail.elt;
    var peligro = origen && origen.classList.contains("boton-peligro");
    var aceptar = dialogo.querySelector('button[value="si"]');
    aceptar.className = "boton " + (peligro ? "boton-peligro" : "boton-principal");

    function alCerrar() {
      dialogo.removeEventListener("close", alCerrar);
      // Escape y el botón de cancelar dejan returnValue vacío o en "no".
      if (dialogo.returnValue === "si") {
        evt.detail.issueRequest(true);
      }
    }

    dialogo.addEventListener("close", alCerrar);
    dialogo.returnValue = "";
    dialogo.showModal();
  });
})();
