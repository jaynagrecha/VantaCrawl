/* Horizon Catalog relative asset — used by /xss/base-tag hijack demos. */
document.addEventListener('DOMContentLoaded', function () {
  var el = document.createElement('pre');
  el.id = 'app-js-loaded';
  el.textContent = 'static/app.js loaded from ' + document.currentScript.src;
  document.body.appendChild(el);
});
