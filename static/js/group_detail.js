(function() {
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

  setupModal('edit-group-btn', 'edit-group-modal', 'edit-group-name');
  setupModal('delete-group-btn', 'delete-group-modal', null);
  setupModal('add-member-btn', 'add-member-modal', 'member-username');

  // Confirm before removing a member
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (!form.dataset.confirmRemove) return;
    if (!confirm('Remove ' + form.dataset.confirmRemove + ' from this group?')) {
      e.preventDefault();
    }
  });

  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    var modals = ['edit-group-modal', 'delete-group-modal', 'add-member-modal'];
    for (var i = 0; i < modals.length; i++) {
      var m = document.getElementById(modals[i]);
      if (m && !m.classList.contains('hidden')) {
        m.classList.add('hidden');
        break;
      }
    }
  });
})();
