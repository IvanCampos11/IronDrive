// IronDrive – group_detail.js
// Group detail page UI: member management modals, add-member typeahead,
// role dropdowns, confirmation dialogs.
(function() {
  function setupModal(btnId, modalId, focusId) {
    var btn = document.getElementById(btnId);
    var modal = document.getElementById(modalId);
    if (!btn || !modal) return;

    btn.addEventListener('click', function() {
      modal.classList.remove('hidden');
      resetMemberSearch();
      if (focusId) {
        var el = document.getElementById(focusId);
        if (el) el.focus();
      }
    });

    modal.addEventListener('click', function(e) {
      if (e.target === modal) {
        modal.classList.add('hidden');
        resetMemberSearch();
      }
    });

    modal.querySelectorAll('[data-modal-close]').forEach(function(el) {
      el.addEventListener('click', function() {
        modal.classList.add('hidden');
        resetMemberSearch();
      });
    });
  }

  setupModal('edit-group-btn', 'edit-group-modal', 'edit-group-name');
  setupModal('delete-group-btn', 'delete-group-modal', null);
  setupModal('add-member-btn', 'add-member-modal', 'member-search-input');

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
        resetMemberSearch();
        break;
      }
    }
  });

  // --- Add member typeahead search ---
  var searchInput = document.getElementById('member-search-input');
  var searchWrapper = document.getElementById('member-search-wrapper');
  var searchDropdown = document.getElementById('member-search-dropdown');
  var selectedPill = document.getElementById('member-selected-pill');
  var pillAvatar = document.getElementById('member-pill-avatar');
  var pillName = document.getElementById('member-pill-name');
  var clearBtn = document.getElementById('member-clear-selection');
  var hiddenUsername = document.getElementById('member-username-hidden');
  var submitBtn = document.getElementById('add-member-submit');

  if (!searchInput) return; // not on group detail page with add permissions

  var debounceTimer = null;
  var activeIndex = -1;

  function resetMemberSearch() {
    if (searchInput) searchInput.value = '';
    if (searchDropdown) { searchDropdown.classList.add('hidden'); searchDropdown.innerHTML = ''; }
    if (selectedPill) selectedPill.classList.add('hidden');
    if (searchWrapper) searchWrapper.classList.remove('hidden');
    if (hiddenUsername) hiddenUsername.value = '';
    if (submitBtn) submitBtn.disabled = true;
    activeIndex = -1;
  }

  function selectUser(name) {
    hiddenUsername.value = name;
    searchInput.value = '';
    searchWrapper.classList.add('hidden');
    searchDropdown.classList.add('hidden');
    pillAvatar.textContent = name.charAt(0).toUpperCase();
    pillName.textContent = name;
    selectedPill.classList.remove('hidden');
    submitBtn.disabled = false;
    activeIndex = -1;
  }

  clearBtn.addEventListener('click', function() {
    hiddenUsername.value = '';
    selectedPill.classList.add('hidden');
    searchWrapper.classList.remove('hidden');
    searchInput.focus();
    submitBtn.disabled = true;
  });

  searchInput.addEventListener('input', function() {
    var q = searchInput.value.trim();
    clearTimeout(debounceTimer);
    activeIndex = -1;

    if (q.length === 0) {
      searchDropdown.classList.add('hidden');
      searchDropdown.innerHTML = '';
      return;
    }

    debounceTimer = setTimeout(function() {
      fetch('/search/grantees?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          searchDropdown.innerHTML = '';
          activeIndex = -1;
          // Filter to users only
          var items = (data.results || []).filter(function(r) { return r.type === 'user'; });

          if (items.length === 0) {
            searchDropdown.innerHTML =
              '<div class="px-4 py-3 text-sm text-gray-400 dark:text-gray-500">No users found</div>';
            searchDropdown.classList.remove('hidden');
            return;
          }

          items.forEach(function(item, idx) {
            var div = document.createElement('div');
            div.setAttribute('role', 'option');
            div.setAttribute('data-index', idx);
            div.className = 'flex items-center gap-3 px-4 py-2.5 cursor-pointer text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';

            div.innerHTML =
              '<div class="flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 text-xs font-bold uppercase flex-shrink-0">' +
              escapeHtml(item.name.charAt(0)) + '</div>' +
              '<span class="truncate">' + escapeHtml(item.name) + '</span>';

            div.addEventListener('click', function() { selectUser(item.name); });
            searchDropdown.appendChild(div);
          });

          searchDropdown.classList.remove('hidden');
        })
        .catch(function() {
          searchDropdown.classList.add('hidden');
        });
    }, 300);
  });

  searchInput.addEventListener('keydown', function(e) {
    var items = searchDropdown.querySelectorAll('[role="option"]');
    if (!items.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, items.length - 1);
      highlightItem(items);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      highlightItem(items);
    } else if (e.key === 'Enter' && activeIndex >= 0) {
      e.preventDefault();
      items[activeIndex].click();
    }
  });

  function highlightItem(items) {
    items.forEach(function(el, i) {
      if (i === activeIndex) {
        el.classList.add('bg-gray-100', 'dark:bg-gray-700');
        el.scrollIntoView({ block: 'nearest' });
      } else {
        el.classList.remove('bg-gray-100', 'dark:bg-gray-700');
      }
    });
  }

  document.addEventListener('mousedown', function(e) {
    if (searchDropdown && !searchDropdown.contains(e.target) && e.target !== searchInput) {
      searchDropdown.classList.add('hidden');
    }
  });

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Permission / role pill dropdown menus ---
  document.addEventListener('click', function(e) {
    var trigger = e.target.closest('[data-permission-trigger]');
    if (trigger) {
      e.stopPropagation();
      var menu = trigger.closest('[data-permission-menu]');
      var dd = menu && menu.querySelector('[data-permission-dropdown]');
      if (!dd) return;
      // Close any other open dropdowns first
      document.querySelectorAll('[data-permission-dropdown]').forEach(function(d) {
        if (d !== dd) d.classList.add('hidden');
      });
      dd.classList.toggle('hidden');
      return;
    }
    // Close all dropdowns if clicking elsewhere
    document.querySelectorAll('[data-permission-dropdown]').forEach(function(d) {
      d.classList.add('hidden');
    });
  });
})();
