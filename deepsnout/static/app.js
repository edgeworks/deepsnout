'use strict';
// No external libraries, tracking, inline handlers or CDN dependencies.
document.querySelectorAll('form[data-confirm]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});
if (document.querySelector('[data-refresh="true"]')) {
  window.setTimeout(() => window.location.reload(), 4000);
}
