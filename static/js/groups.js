(function() {
  const btn = document.getElementById('create-group-btn');
  const modal = document.getElementById('create-group-modal');
  if (!btn || !modal) return;

  btn.addEventListener('click', function() {
    modal.classList.remove('hidden');
    const nameInput = document.getElementById('group-name');
    if (nameInput) nameInput.focus();
  });

  modal.addEventListener('click', function(e) {
    if (e.target === modal) modal.classList.add('hidden');
  });

  modal.querySelectorAll('[data-modal-close]').forEach(function(el) {
    el.addEventListener('click', function() { modal.classList.add('hidden'); });
  });

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
      modal.classList.add('hidden');
    }
  });
})();
