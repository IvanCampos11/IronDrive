// IronDrive – spaces.js
// Space settings UI: create/delete modals, grant-access typeahead,
// permission-level dropdown menus.
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
      if (e.target === modal) {
        modal.classList.add('hidden');
        resetGrantSearch();
      }
    });

    modal.querySelectorAll('[data-modal-close]').forEach(function(el) {
      el.addEventListener('click', function() {
        modal.classList.add('hidden');
        resetGrantSearch();
      });
    });
  }

  setupModal('create-space-btn', 'create-space-modal', 'space-name');
  setupModal('delete-space-btn', 'delete-space-modal', null);
  setupModal('grant-access-btn', 'grant-access-modal', 'grant-search');

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
        resetGrantSearch();
        break;
      }
    }
  });

  // --- Grant access typeahead ---
  var searchInput = document.getElementById('grant-search');
  var dropdown = document.getElementById('grant-dropdown');
  var resultsList = document.getElementById('grant-results');
  var selectedDiv = document.getElementById('grant-selected');
  var selectedIcon = document.getElementById('grant-selected-icon');
  var selectedName = document.getElementById('grant-selected-name');
  var clearBtn = document.getElementById('grant-clear-selection');
  var granteeTypeInput = document.getElementById('grant-grantee-type');
  var granteeIdInput = document.getElementById('grant-grantee-id');
  var submitBtn = document.getElementById('grant-submit-btn');

  if (!searchInput) return; // not on settings page

  var debounceTimer = null;
  var activeIndex = -1;

  function resetGrantSearch() {
    if (searchInput) searchInput.value = '';
    if (dropdown) dropdown.classList.add('hidden');
    if (resultsList) resultsList.innerHTML = '';
    if (selectedDiv) selectedDiv.classList.add('hidden');
    if (granteeTypeInput) granteeTypeInput.value = '';
    if (granteeIdInput) granteeIdInput.value = '';
    if (submitBtn) submitBtn.disabled = true;
    if (searchInput) searchInput.classList.remove('hidden');
    activeIndex = -1;
  }

  function selectResult(type, id, name) {
    granteeTypeInput.value = type;
    granteeIdInput.value = id;
    searchInput.value = '';
    searchInput.classList.add('hidden');
    dropdown.classList.add('hidden');

    var icon = type === 'group'
      ? '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>'
      : '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>';
    selectedIcon.innerHTML = icon;
    selectedName.textContent = name;
    selectedDiv.classList.remove('hidden');
    submitBtn.disabled = false;
    activeIndex = -1;
  }

  clearBtn.addEventListener('click', function() {
    granteeTypeInput.value = '';
    granteeIdInput.value = '';
    selectedDiv.classList.add('hidden');
    searchInput.classList.remove('hidden');
    searchInput.focus();
    submitBtn.disabled = true;
  });

  searchInput.addEventListener('input', function() {
    var q = searchInput.value.trim();
    clearTimeout(debounceTimer);
    activeIndex = -1;

    if (q.length === 0) {
      dropdown.classList.add('hidden');
      resultsList.innerHTML = '';
      return;
    }

    debounceTimer = setTimeout(function() {
      fetch('/search/grantees?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          resultsList.innerHTML = '';
          activeIndex = -1;
          var items = data.results || [];

          if (items.length === 0) {
            resultsList.innerHTML =
              '<li class="px-4 py-3 text-sm text-gray-400 dark:text-gray-500">No users or groups found</li>';
            dropdown.classList.remove('hidden');
            return;
          }

          items.forEach(function(item, idx) {
            var li = document.createElement('li');
            li.setAttribute('role', 'option');
            li.setAttribute('data-index', idx);
            li.className = 'flex items-center gap-3 px-4 py-2.5 cursor-pointer text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';

            var icon = item.type === 'group'
              ? '<svg class="w-4 h-4 flex-shrink-0 text-amber-500 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>'
              : '<svg class="w-4 h-4 flex-shrink-0 text-blue-500 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>';

            var badge = item.type === 'group'
              ? '<span class="ml-auto text-xs px-1.5 py-0.5 rounded-full bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-300">group</span>'
              : '<span class="ml-auto text-xs px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300">user</span>';

            li.innerHTML = icon + '<span class="truncate">' + escapeHtml(item.name) + '</span>' + badge;
            li.addEventListener('click', function() {
              selectResult(item.type, item.id, item.name);
            });
            resultsList.appendChild(li);
          });

          dropdown.classList.remove('hidden');
        })
        .catch(function() {
          dropdown.classList.add('hidden');
        });
    }, 300);
  });

  // Keyboard navigation for dropdown
  searchInput.addEventListener('keydown', function(e) {
    var items = resultsList.querySelectorAll('[role="option"]');
    if (!items.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, items.length - 1);
      updateActiveItem(items);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      updateActiveItem(items);
    } else if (e.key === 'Enter' && activeIndex >= 0) {
      e.preventDefault();
      items[activeIndex].click();
    }
  });

  function updateActiveItem(items) {
    items.forEach(function(li, i) {
      if (i === activeIndex) {
        li.classList.add('bg-gray-100', 'dark:bg-gray-700');
        li.scrollIntoView({ block: 'nearest' });
      } else {
        li.classList.remove('bg-gray-100', 'dark:bg-gray-700');
      }
    });
  }

  // Close dropdown when clicking outside
  document.addEventListener('mousedown', function(e) {
    if (dropdown && !dropdown.contains(e.target) && e.target !== searchInput) {
      dropdown.classList.add('hidden');
    }
  });

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Permission pill dropdown menus ---
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
