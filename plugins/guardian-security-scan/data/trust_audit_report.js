// View selection and copy-only handoffs. No network requests or execution.
function setView(name) {
  document.querySelectorAll('.view').forEach(el => {
    el.hidden = el.id !== 'view-' + name;
  });
  document.querySelectorAll('[data-view]').forEach(el => {
    const active = el.dataset.view === name;
    el.classList.toggle('active', active);
    el.setAttribute('aria-pressed', String(active));
  });
}
document.querySelectorAll('[data-view]').forEach(el => {
  el.addEventListener('click', () => setView(el.dataset.view));
});
document.querySelectorAll('.copy').forEach(el => {
  el.addEventListener('click', async () => {
    const area = document.getElementById(el.dataset.prompt);
    const status = document.getElementById(el.dataset.status);
    try {
      await navigator.clipboard.writeText(area.value);
      status.textContent = 'Copied. Paste into your project chat for a read-only review.';
    } catch {
      area.closest('details').open = true;
      area.focus();
      area.select();
      status.textContent = 'Select and copy the prompt below. No action has been executed.';
    }
  });
});
setView(document.body.dataset.initialView);
