(function() {
  // --- Spaces index: create space modal ---
  function setupModal(btnId, modalId, focusId) {
    var btn = document.getElementById(btnId);
    var modal = document.getElementById(modalId);
    if (!btn || !modal) return;

    btn.addEventListener('click', function() {
      modal.classList.remove('hidden');
      if (focusId) {
        var el = document.getElementById(focusId);
        if (el) el.focus();
      }
    });

    modal.addEventListener('click', function(e) {
      if (e.target === modal) modal.classList.add('hidden');
    });

    modal.querySelectorAll('[data-modal-close]').forEach(function(el) {
      el.addEventListener('click', function() { modal.classList.add('hidden'); });
    });
  }

  setupModal('create-space-btn', 'create-space-modal', 'space-name');
  setupModal('delete-space-btn', 'delete-space-modal', null);
  setupModal('grant-access-btn', 'grant-access-modal', 'grant-name');

  // Confirm before revoking access
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (!form.dataset.confirmRevoke) return;
    if (!confirm('Revoke access for ' + form.dataset.confirmRevoke + '?')) {
      e.preventDefault();
    }
  });

  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    var modals = ['create-space-modal', 'delete-space-modal', 'grant-access-modal'];
    for (var i = 0; i < modals.length; i++) {
      var m = document.getElementById(modals[i]);
      if (m && !m.classList.contains('hidden')) {
        m.classList.add('hidden');
        break;
      }
    }
  });
})();
