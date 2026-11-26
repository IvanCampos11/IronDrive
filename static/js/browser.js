// IronDrive – browser.js
// File browser for personal libraries and spaces: selection, context menus,
// file operations, sorting/filtering, list/grid view, uploads and downloads.
// Requires core.js (window.IronDrive).
(function () {
  'use strict';

  var ID = window.IronDrive;
  var browser = document.getElementById('browser');
  if (!ID || !browser) return;

  var BASE = browser.getAttribute('data-base');
  // Personal trash is /trash; a space's is /spaces/<id>/trash.
  var TRASH_BASE = BASE === '/files' ? '/trash' : BASE + '/trash';
  var CAN_WRITE = browser.getAttribute('data-can-write') === 'true';
  var CHUNK_SIZE = positiveInt(browser.getAttribute('data-chunk-size-bytes'), 8 * 1024 * 1024);
  var MAX_PARALLEL_CHUNKS = Math.min(positiveInt(browser.getAttribute('data-max-parallel-chunks'), 4), 8);
  var MAX_PARALLEL_FILES = 3;
  var coarsePointer = window.matchMedia('(pointer: coarse)');

  function positiveInt(raw, fallback) {
    var n = parseInt(raw || '', 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  }

  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

  // -------------------------------------------------------------------------
  // DOM accessors (the listing is replaced on every navigation)
  // -------------------------------------------------------------------------
  function view() { return document.querySelector('#file-browser-content .browser-view'); }
  function listing() { return document.querySelector('#file-browser-content .listing'); }
  function items() { return Array.prototype.slice.call(document.querySelectorAll('#file-browser-content .item')); }
  function visibleItems() { return items().filter(function (i) { return !i.hidden; }); }
  function itemByPath(p) {
    return items().find(function (i) { return i.getAttribute('data-path') === p; }) || null;
  }
  function currentPath() { var v = view(); return v ? v.getAttribute('data-path') || '' : ''; }
  function isDir(item) { return item.getAttribute('data-is-dir') === 'true'; }
  function nameOf(item) { return item.getAttribute('data-name') || ''; }
  function pathOf(item) { return item.getAttribute('data-path') || ''; }

  function joinPath(dir, name) { return dir ? dir + '/' + name : name; }
  function parentOf(p) { var i = p.lastIndexOf('/'); return i < 0 ? '' : p.slice(0, i); }
  function listingUrl(p) { return BASE + (p ? '?path=' + encodeURIComponent(p) : ''); }
  function partialUrl(p) { return BASE + '/partial' + (p ? '?path=' + encodeURIComponent(p) : ''); }

  // -------------------------------------------------------------------------
  // Navigation + refresh
  // -------------------------------------------------------------------------
  var afterRefresh = null;

  function navigate(p) {
    window.htmx.ajax('GET', partialUrl(p), { target: '#file-browser-content', swap: 'innerHTML' }).then(function () {
      history.pushState({ htmx: true }, '', listingUrl(p));
    });
  }

  /** Reload the current folder in place, optionally selecting paths afterwards. */
  function refresh(selectPaths) {
    afterRefresh = selectPaths || null;
    return window.htmx.ajax('GET', partialUrl(currentPath()), { target: '#file-browser-content', swap: 'innerHTML' });
  }

  function onListingSwapped() {
    detailsCache.clear();
    syncDetailsToggle();
    selection.clear();
    anchorPath = null;
    applyView();
    applySort();
    var filter = document.getElementById('browser-filter');
    if (filter) filter.value = '';
    var v = view();
    if (v) {
      var title = v.getAttribute('data-title');
      if (title) document.title = title + ' – IronDrive';
    }
    var dzTarget = document.getElementById('drop-zone-target');
    if (dzTarget && v) dzTarget.textContent = v.getAttribute('data-title') || 'this folder';
    if (afterRefresh) {
      var wanted = afterRefresh;
      afterRefresh = null;
      wanted.forEach(function (p) { if (itemByPath(p)) selection.add(p); });
      var first = wanted.length ? itemByPath(wanted[0]) : null;
      if (first) { focusItem(first); first.scrollIntoView({ block: 'nearest' }); }
    }
    renderSelection();
  }

  document.addEventListener('htmx:afterSwap', function (e) {
    if (e.detail.target && e.detail.target.id === 'file-browser-content') onListingSwapped();
  });
  document.addEventListener('htmx:historyRestore', function () { onListingSwapped(); });

  // -------------------------------------------------------------------------
  // View mode (list / grid)
  // -------------------------------------------------------------------------
  var viewMode = 'list';
  try { viewMode = localStorage.getItem('irondrive-view') === 'grid' ? 'grid' : 'list'; } catch (_) { /* ignore */ }

  function applyView() {
    var l = listing();
    if (l) l.setAttribute('data-view', viewMode);
    document.querySelectorAll('[data-view-btn]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-view-btn') === viewMode));
    });
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-view-btn]');
    if (!b) return;
    viewMode = b.getAttribute('data-view-btn');
    try { localStorage.setItem('irondrive-view', viewMode); } catch (_) { /* ignore */ }
    applyView();
  });

  // -------------------------------------------------------------------------
  // Sorting (client-side; folders always first since they're separate groups)
  // -------------------------------------------------------------------------
  var sort = { key: 'name', asc: true };
  var collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  function applySort() {
    document.querySelectorAll('#file-browser-content .items').forEach(function (group) {
      var rows = Array.prototype.slice.call(group.children);
      rows.sort(function (a, b) {
        var r;
        if (sort.key === 'size') r = (+a.getAttribute('data-size') || 0) - (+b.getAttribute('data-size') || 0);
        else if (sort.key === 'modified') r = (a.getAttribute('data-modified') || '').localeCompare(b.getAttribute('data-modified') || '');
        else r = 0;
        if (r === 0) r = collator.compare(nameOf(a), nameOf(b));
        return sort.asc ? r : -r;
      });
      rows.forEach(function (r) { group.appendChild(r); });
    });
    document.querySelectorAll('[data-sort]').forEach(function (btn) {
      var ind = btn.querySelector('.sort-ind');
      var active = btn.getAttribute('data-sort') === sort.key;
      btn.classList.toggle('text-fg', active);
      btn.setAttribute('aria-sort', active ? (sort.asc ? 'ascending' : 'descending') : 'none');
      if (ind) { ind.hidden = !active; ind.textContent = sort.asc ? 'arrow_upward' : 'arrow_downward'; }
    });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-sort]');
    if (!btn) return;
    var key = btn.getAttribute('data-sort');
    // Newest/largest first is the more useful default for those columns.
    sort = sort.key === key ? { key: key, asc: !sort.asc } : { key: key, asc: key === 'name' };
    applySort();
  });

  // -------------------------------------------------------------------------
  // Filter ("Search in this folder")
  // -------------------------------------------------------------------------
  var filterInput = document.getElementById('browser-filter');
  if (filterInput) {
    filterInput.addEventListener('input', applyFilter);
    filterInput.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { filterInput.value = ''; applyFilter(); filterInput.blur(); }
      if (e.key === 'ArrowDown' || e.key === 'Enter') {
        var first = visibleItems()[0];
        if (first) { e.preventDefault(); selectOnly(first); focusItem(first); }
      }
    });
  }

  function applyFilter() {
    var q = (filterInput && filterInput.value || '').trim().toLocaleLowerCase();
    var shown = 0;
    items().forEach(function (i) {
      var match = !q || nameOf(i).toLocaleLowerCase().indexOf(q) !== -1;
      i.hidden = !match;
      if (match) shown++;
      if (!match && selection.has(pathOf(i))) selection.delete(pathOf(i));
    });
    document.querySelectorAll('#file-browser-content .items').forEach(function (g) {
      var section = g.closest('section');
      if (section) section.hidden = !Array.prototype.some.call(g.children, function (c) { return !c.hidden; });
    });
    var l = listing();
    var note = document.getElementById('filter-empty');
    if (l && q && shown === 0) {
      if (!note) {
        note = ID.el('p', 'px-6 py-16 text-center text-muted');
        note.id = 'filter-empty';
        l.appendChild(note);
      }
      note.textContent = 'No items in this folder match “' + filterInput.value.trim() + '”.';
    } else if (note) {
      note.remove();
    }
    renderSelection();
  }

  document.addEventListener('keydown', function (e) {
    if (e.key !== '/' || !filterInput || isTyping(e.target)) return;
    e.preventDefault();
    filterInput.focus();
  });

  function isTyping(t) {
    return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
  }

  // -------------------------------------------------------------------------
  // Selection
  // -------------------------------------------------------------------------
  var selection = new Set();
  var anchorPath = null;

  function renderSelection() {
    var all = items();
    all.forEach(function (i) {
      var on = selection.has(pathOf(i));
      i.setAttribute('aria-selected', String(on));
      var cb = i.querySelector('.item-check .check');
      if (cb) cb.checked = on;
    });
    var l = listing();
    if (l) l.classList.toggle('has-selection', selection.size > 0);
    var bar = document.getElementById('selection-bar');
    if (bar) {
      bar.hidden = selection.size === 0;
      var count = document.getElementById('selection-count');
      if (count) count.textContent = selection.size + ' selected';
    }
    var selectAll = document.getElementById('select-all');
    if (selectAll) {
      var visible = visibleItems().length;
      selectAll.checked = visible > 0 && selection.size === visible;
      selectAll.indeterminate = selection.size > 0 && selection.size < visible;
    }
    updateDetails();
  }

  function selectOnly(item) {
    selection.clear();
    selection.add(pathOf(item));
    anchorPath = pathOf(item);
    renderSelection();
  }

  function toggle(item) {
    var p = pathOf(item);
    if (selection.has(p)) selection.delete(p); else selection.add(p);
    anchorPath = p;
    renderSelection();
  }

  function selectRange(item, additive) {
    var list = visibleItems();
    var a = list.findIndex(function (i) { return pathOf(i) === anchorPath; });
    var b = list.indexOf(item);
    if (a < 0) { selectOnly(item); return; }
    if (!additive) selection.clear();
    for (var k = Math.min(a, b); k <= Math.max(a, b); k++) selection.add(pathOf(list[k]));
    renderSelection();
  }

  function selectedItems() {
    return items().filter(function (i) { return selection.has(pathOf(i)); });
  }

  function focusItem(item) {
    items().forEach(function (i) { i.tabIndex = -1; });
    item.tabIndex = 0;
    item.focus({ preventScroll: false });
  }

  // Click handling: name link opens, checkbox toggles, row click selects.
  document.addEventListener('click', function (e) {
    if (suppressClick) { suppressClick = false; return; }
    var item = e.target.closest('#file-browser-content .item');
    if (!item) {
      // Click on empty space in the content area clears the selection.
      if (selection.size && e.target.closest('#main') && !e.target.closest('#selection-bar, .listing-head, button, a, input, dialog, .menu')) {
        selection.clear();
        renderSelection();
      }
      return;
    }

    if (e.target.closest('.item-check')) {
      if (e.target.matches('.check')) {
        e.preventDefault();
        if (e.shiftKey && anchorPath) selectRange(item, true); else toggle(item);
        focusItem(item);
      }
      return;
    }

    var actionBtn = e.target.closest('[data-item-action]');
    if (actionBtn) {
      e.preventDefault();
      var action = actionBtn.getAttribute('data-item-action');
      if (action === 'menu') {
        if (!selection.has(pathOf(item))) selectOnly(item);
        openItemMenu(actionBtn, null);
      } else {
        selectOnly(item);
        runAction(action, [item]);
      }
      return;
    }

    var link = e.target.closest('a.item-name');
    var modified = e.ctrlKey || e.metaKey || e.shiftKey;
    if (link && !modified) {
      // Folders navigate via hx-get on the link; files download through us.
      if (!isDir(item)) { e.preventDefault(); downloadItems([item]); }
      return;
    }
    if (link) e.preventDefault();

    if (coarsePointer.matches && !modified && selection.size === 0) { openItem(item); return; }
    if (e.shiftKey) selectRange(item, e.ctrlKey || e.metaKey);
    else if (e.ctrlKey || e.metaKey) toggle(item);
    else selectOnly(item);
    focusItem(item);
  });

  document.addEventListener('dblclick', function (e) {
    var item = e.target.closest('#file-browser-content .item');
    if (!item || e.target.closest('.item-check, [data-item-action]')) return;
    openItem(item);
  });

  document.addEventListener('change', function (e) {
    if (e.target.id !== 'select-all') return;
    if (e.target.checked) visibleItems().forEach(function (i) { selection.add(pathOf(i)); });
    else selection.clear();
    renderSelection();
  });

  function openItem(item) {
    if (isDir(item)) navigate(pathOf(item));
    else downloadItems([item]);
  }

  // Keyboard: arrows move, Shift extends, Space toggles, Enter opens,
  // Delete removes, F2 renames, Ctrl+A selects all, Escape clears.
  document.addEventListener('keydown', function (e) {
    if (document.querySelector('dialog[open]') || isTyping(e.target)) return;
    var item = e.target.closest && e.target.closest('#file-browser-content .item');
    var list = visibleItems();
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && list.length && (item || e.target === document.body)) {
      e.preventDefault();
      list.forEach(function (i) { selection.add(pathOf(i)); });
      renderSelection();
      return;
    }
    if (e.key === 'Escape' && selection.size) { selection.clear(); renderSelection(); return; }
    if (!item) {
      if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && list.length && e.target === document.body) {
        e.preventDefault();
        selectOnly(list[0]);
        focusItem(list[0]);
      }
      return;
    }
    var idx = list.indexOf(item);
    var grid = viewMode === 'grid';
    var step = { ArrowDown: 1, ArrowUp: -1, ArrowRight: grid ? 1 : 0, ArrowLeft: grid ? -1 : 0 }[e.key];
    if (step) {
      e.preventDefault();
      var next = list[Math.max(0, Math.min(list.length - 1, idx + step))];
      if (e.shiftKey) selectRange(next, false); else selectOnly(next);
      focusItem(next);
      return;
    }
    if (e.key === ' ') { e.preventDefault(); toggle(item); return; }
    if (e.key === 'Enter') { e.preventDefault(); openItem(item); return; }
    if ((e.key === 'Delete' || e.key === 'Backspace') && CAN_WRITE && selection.size) { e.preventDefault(); runAction('delete', selectedItems()); return; }
    if (e.key === 'F2' && CAN_WRITE) { e.preventDefault(); runAction('rename', [item]); }
  });

  // -------------------------------------------------------------------------
  // Context menu
  // -------------------------------------------------------------------------
  var itemMenu = document.getElementById('item-menu');

  function menuButton(action, iconName, label, danger) {
    var b = ID.el('button', danger ? 'menu-item-danger' : 'menu-item');
    b.type = 'button';
    b.setAttribute('role', 'menuitem');
    b.setAttribute('data-menu-action', action);
    b.appendChild(ID.icon(iconName));
    b.appendChild(document.createTextNode(label));
    return b;
  }

  function openItemMenu(anchor, point) {
    var sel = selectedItems();
    if (!sel.length || !itemMenu) return;
    itemMenu.replaceChildren();
    var files = sel.filter(function (i) { return !isDir(i); });
    if (sel.length === 1) {
      if (isDir(sel[0])) itemMenu.appendChild(menuButton('open', 'folder_open', 'Open'));
      else itemMenu.appendChild(menuButton('download', 'download', 'Download'));
      if (CAN_WRITE) itemMenu.appendChild(menuButton('rename', 'edit', 'Rename'));
    } else if (files.length) {
      itemMenu.appendChild(menuButton('download', 'download', 'Download ' + plural(files.length, 'file')));
    }
    if (CAN_WRITE) {
      itemMenu.appendChild(menuButton('move', 'drive_file_move', 'Move to…'));
      itemMenu.appendChild(ID.el('div', 'menu-sep'));
      itemMenu.appendChild(menuButton('delete', 'delete', sel.length === 1 ? 'Delete' : 'Delete ' + plural(sel.length, 'item'), true));
    }
    if (!itemMenu.children.length) return;
    ID.showMenu(itemMenu, anchor, point);
  }

  document.addEventListener('contextmenu', function (e) {
    var item = e.target.closest('#file-browser-content .item');
    if (!item || e.shiftKey) return; // Shift+right-click keeps the native menu.
    e.preventDefault();
    if (!selection.has(pathOf(item))) selectOnly(item);
    focusItem(item);
    openItemMenu(null, { x: e.clientX, y: e.clientY });
  });

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-menu-action]');
    if (b) { ID.closeMenus(); runAction(b.getAttribute('data-menu-action'), selectedItems()); return; }
    var s = e.target.closest('[data-sel]');
    if (s) {
      var a = s.getAttribute('data-sel');
      if (a === 'clear') { selection.clear(); renderSelection(); } else runAction(a, selectedItems());
    }
  });

  // -------------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------------
  function runAction(action, list) {
    if (!list.length) return;
    if (action === 'open') openItem(list[0]);
    else if (action === 'download') downloadItems(list);
    else if (action === 'rename') openRename(list[0]);
    else if (action === 'move') openMove(list.map(pathOf));
    else if (action === 'delete') deleteItems(list);
  }

  function reportBulk(result, verbed, total) {
    var ok = result[verbed] || 0;
    var errors = result.errors || [];
    if (errors.length) {
      ID.toast(ok ? (ok + ' of ' + total + ' ' + verbed + '. ' + errors[0]) : errors[0], { error: true });
    }
    return ok;
  }

  // Delete moves items to the trash, so there's no confirmation: the snackbar
  // offers Undo instead.
  function deleteItems(list) {
    if (!CAN_WRITE || !list.length) return;
    var names = list.map(nameOf);
    ID.request(BASE + '/bulk-delete', { method: 'POST', json: { paths: list.map(pathOf) } })
      .then(function (res) {
        var ok = reportBulk(res, 'deleted', list.length);
        var ids = res.trash_ids || [];
        if (ok && !(res.errors || []).length) {
          ID.toast(list.length === 1 ? '“' + names[0] + '” moved to trash' : plural(ok, 'item') + ' moved to trash', {
            timeout: 8000,
            action: ids.length ? { label: 'Undo', onClick: function () { undoDelete(ids); } } : null,
          });
        }
        refresh();
        ID.refreshUsage();
      })
      .catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  function undoDelete(ids) {
    ID.request(TRASH_BASE + '/restore', { method: 'POST', json: { ids: ids } })
      .then(function (res) {
        var restored = (res.restored || []).map(function (r) { return r.path; });
        if ((res.errors || []).length) ID.toast(res.errors[0], { error: true });
        // Select what came back if it's in the folder being shown.
        refresh(restored);
        ID.refreshUsage();
      })
      .catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  // New folder ---------------------------------------------------------------
  function openNewFolder() {
    if (!CAN_WRITE) return;
    var d = document.getElementById('mkdir-dialog');
    if (!d) return;
    var form = d.querySelector('form');
    form.elements.path.value = currentPath();
    form.elements.name.value = uniqueName('Untitled folder');
    ID.openDialog(d);
  }

  function uniqueName(name) {
    var taken = new Set(items().map(nameOf));
    if (!taken.has(name)) return name;
    var dot = name.lastIndexOf('.');
    var stem = dot > 0 ? name.slice(0, dot) : name;
    var ext = dot > 0 ? name.slice(dot) : '';
    for (var n = 1; n < 1000; n++) {
      var candidate = stem + ' (' + n + ')' + ext;
      if (!taken.has(candidate)) return candidate;
    }
    return stem + ' (' + Date.now() + ')' + ext;
  }

  // Rename ---------------------------------------------------------------------
  function openRename(item) {
    if (!CAN_WRITE) return;
    var d = document.getElementById('rename-dialog');
    if (!d) return;
    var form = d.querySelector('form');
    var name = nameOf(item);
    form.elements.old_path.value = pathOf(item);
    form.elements.new_name.value = name;
    ID.openDialog(d);
    // Select the name without its extension, like a desktop file manager.
    var dot = name.lastIndexOf('.');
    if (!isDir(item) && dot > 0) form.elements.new_name.setSelectionRange(0, dot);
  }

  // Both dialogs submit via the JSON endpoints.
  document.addEventListener('submit', function (e) {
    var form = e.target;
    var op = form.getAttribute && form.getAttribute('data-op');
    if (op !== 'mkdir' && op !== 'rename') return;
    e.preventDefault();
    var d = form.closest('dialog');
    var submit = form.querySelector('button[type=submit]');
    var req;
    if (op === 'mkdir') {
      var name = form.elements.name.value.trim();
      req = ID.request(BASE + '/api/mkdir', { method: 'POST', json: { path: form.elements.path.value, name: name } })
        .then(function (res) { ID.toast('Folder “' + name + '” created'); return res.path; });
    } else {
      var newName = form.elements.new_name.value.trim();
      var oldPath = form.elements.old_path.value;
      if (newName === oldPath.split('/').pop()) { ID.closeDialog(d); return; }
      req = ID.request(BASE + '/api/rename', { method: 'POST', json: { path: oldPath, new_name: newName } })
        .then(function (res) { ID.toast('Renamed to “' + newName + '”'); return res.path; });
    }
    submit.disabled = true;
    req.then(function (newPath) {
      ID.closeDialog(d);
      return refresh(newPath ? [newPath] : null);
    }).catch(function (err) {
      ID.dialogError(d, err.message);
    }).finally(function () { submit.disabled = false; });
  });

  // Move -------------------------------------------------------------------------
  var move = { sources: [], dir: '' };

  function openMove(paths) {
    if (!CAN_WRITE) return;
    var d = document.getElementById('move-dialog');
    if (!d) return;
    move.sources = paths;
    var names = paths.map(function (p) { return p.split('/').pop(); });
    document.getElementById('move-dialog-subtitle').textContent =
      paths.length === 1 ? '“' + names[0] + '”' : plural(paths.length, 'item');
    ID.openDialog(d);
    loadMoveFolder(currentPath());
  }

  function invalidTarget(dir) {
    return move.sources.some(function (s) { return dir === s || dir.indexOf(s + '/') === 0; });
  }

  function loadMoveFolder(dir) {
    move.dir = dir;
    var rootName = document.querySelector('#file-browser-content nav[aria-label=Breadcrumb] a, #file-browser-content nav[aria-label=Breadcrumb] span[aria-current]');
    document.getElementById('move-location').textContent = dir ? dir.split('/').pop() : (rootName ? rootName.textContent.trim() : 'Home');
    document.getElementById('move-up').disabled = !dir;
    var confirmBtn = document.getElementById('move-confirm');
    var sameParent = move.sources.every(function (s) { return parentOf(s) === dir; });
    confirmBtn.disabled = sameParent || invalidTarget(dir);
    var list = document.getElementById('move-folders');
    list.replaceChildren(ID.el('li', 'px-6 py-3 text-muted', 'Loading…'));
    ID.request(BASE + '/folders?path=' + encodeURIComponent(dir)).then(function (res) {
      if (move.dir !== dir) return;
      var folders = (res.entries || []).filter(function (f) { return !invalidTarget(f.path); });
      folders.sort(function (a, b) { return collator.compare(a.name, b.name); });
      list.replaceChildren();
      if (!folders.length) list.appendChild(ID.el('li', 'px-6 py-3 text-muted', 'No folders here'));
      folders.forEach(function (f) {
        var li = ID.el('li');
        var b = ID.el('button', 'w-full flex items-center gap-3 h-11 px-6 text-left hover:bg-fg/[0.06] focus:bg-fg/[0.06] focus:outline-none');
        b.type = 'button';
        b.appendChild(ID.icon('folder', 'ms-fill text-muted'));
        b.appendChild(ID.el('span', 'flex-1 truncate', f.name));
        b.appendChild(ID.icon('chevron_right', 'text-subtle'));
        b.addEventListener('click', function () { loadMoveFolder(f.path); });
        li.appendChild(b);
        list.appendChild(li);
      });
    }).catch(function (err) {
      list.replaceChildren(ID.el('li', 'px-6 py-3 text-danger', err.message));
    });
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('#move-up')) { loadMoveFolder(parentOf(move.dir)); return; }
    if (e.target.closest('#move-confirm')) {
      var d = document.getElementById('move-dialog');
      var sources = move.sources.slice();
      var target = move.dir;
      ID.closeDialog(d);
      moveItems(sources, target);
    }
  });

  function moveItems(paths, targetDir) {
    if (!paths.length || invalidTargetFor(paths, targetDir)) return;
    var label = targetDir ? '“' + targetDir.split('/').pop() + '”' : 'the top folder';
    ID.request(BASE + '/bulk-move', { method: 'POST', json: { paths: paths, target_dir: targetDir } })
      .then(function (res) {
        var ok = reportBulk(res, 'moved', paths.length);
        if (ok && !(res.errors || []).length) {
          ID.toast((paths.length === 1 ? '“' + paths[0].split('/').pop() + '”' : plural(ok, 'item')) + ' moved to ' + label, {
            action: { label: 'Open', onClick: function () { navigate(targetDir); } },
          });
        }
        refresh();
      })
      .catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  function invalidTargetFor(paths, dir) {
    return paths.some(function (s) { return dir === s || dir.indexOf(s + '/') === 0 || parentOf(s) === dir; });
  }

  // Drag items onto folders (or breadcrumbs) to move them ---------------------
  var dragPaths = null;

  document.addEventListener('dragstart', function (e) {
    var item = e.target.closest && e.target.closest('#file-browser-content .item');
    if (!item || !CAN_WRITE) return;
    if (!selection.has(pathOf(item))) selectOnly(item);
    dragPaths = selectedItems().map(pathOf);
    selectedItems().forEach(function (i) { i.classList.add('is-dragging'); });
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('application/x-irondrive-paths', JSON.stringify(dragPaths));
    e.dataTransfer.setData('text/plain', dragPaths.join('\n'));
  });

  document.addEventListener('dragend', function () {
    dragPaths = null;
    document.querySelectorAll('.is-dragging, .is-drop-target').forEach(function (i) {
      i.classList.remove('is-dragging', 'is-drop-target');
    });
  });

  function dropTargetFor(e) {
    var crumb = e.target.closest && e.target.closest('[data-drop-path]');
    if (crumb) return { el: crumb, path: crumb.getAttribute('data-drop-path') };
    var item = e.target.closest && e.target.closest('#file-browser-content .item[data-is-dir="true"]');
    if (item) return { el: item, path: pathOf(item) };
    return null;
  }

  document.addEventListener('dragover', function (e) {
    if (!dragPaths) return;
    var t = dropTargetFor(e);
    document.querySelectorAll('.is-drop-target').forEach(function (x) { if (!t || x !== t.el) x.classList.remove('is-drop-target'); });
    if (!t || invalidTargetFor(dragPaths, t.path)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    t.el.classList.add('is-drop-target');
  });

  document.addEventListener('drop', function (e) {
    if (!dragPaths) return;
    var t = dropTargetFor(e);
    if (!t || invalidTargetFor(dragPaths, t.path)) return;
    e.preventDefault();
    var paths = dragPaths;
    dragPaths = null;
    moveItems(paths, t.path);
  });

  // -------------------------------------------------------------------------
  // Downloads
  // -------------------------------------------------------------------------
  function saveBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }

  function downloadItems(list) {
    var files = list.filter(function (i) { return !isDir(i); });
    if (!files.length) { ID.toast('Folders can’t be downloaded yet — open the folder and select its files.'); return; }
    if (files.length < list.length) ID.toast('Skipping folders — only files are downloaded.');
    // One at a time so the browser doesn't block a burst of saves.
    files.reduce(function (chain, item) {
      return chain.then(function () { return downloadOne(pathOf(item), nameOf(item), +item.getAttribute('data-size') || 0); });
    }, Promise.resolve());
  }

  function downloadOne(path, name, size) {
    var controller = new AbortController();
    var t = ID.addTransfer({ name: name, kind: 'download', onCancel: function () { controller.abort(); } });
    var run = size > CHUNK_SIZE ? downloadChunked(path, t, controller.signal) : downloadSingle(path, size, t, controller.signal);
    return run.then(function (blob) {
      saveBlob(blob, name);
      t.done(ID.formatBytes(blob.size));
    }).catch(function (err) {
      if (controller.signal.aborted) t.cancelled(); else t.fail(err.message);
    });
  }

  function fetchOk(url, signal) {
    return fetch(url, { headers: { 'X-CSRF-Token': ID.csrf() }, credentials: 'same-origin', signal: signal }).then(function (resp) {
      if (resp.ok) return resp;
      if (resp.status === 401) window.location.href = '/login';
      return resp.text().then(function (txt) {
        var payload = null;
        try { payload = JSON.parse(txt); } catch (_) { /* not JSON */ }
        throw new Error(ID.errorMessage(payload, 'Download failed (' + resp.status + ')'));
      });
    });
  }

  function downloadSingle(path, size, t, signal) {
    return fetchOk(BASE + '/download?path=' + encodeURIComponent(path), signal).then(function (resp) {
      var total = +resp.headers.get('Content-Length') || size;
      if (!resp.body || !total) return resp.blob();
      var reader = resp.body.getReader();
      var parts = [];
      var got = 0;
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) return new Blob(parts);
          parts.push(r.value);
          got += r.value.length;
          t.progress(got / total, ID.formatBytes(got) + ' of ' + ID.formatBytes(total));
          return pump();
        });
      }
      return pump();
    });
  }

  function downloadChunked(path, t, signal) {
    return ID.request(BASE + '/chunked/download/init?path=' + encodeURIComponent(path)).then(function (init) {
      var total = init.total_chunks || 0;
      var parts = [];
      var got = 0;
      var chain = Promise.resolve();
      for (var i = 0; i < total; i++) {
        (function (idx) {
          chain = chain.then(function () {
            return fetchOk(BASE + '/chunked/download/chunk?token=' + encodeURIComponent(init.token) + '&index=' + idx, signal)
              .then(function (r) { return r.arrayBuffer(); })
              .then(function (buf) {
                parts.push(buf);
                got += buf.byteLength;
                t.progress(got / init.total_bytes, ID.formatBytes(got) + ' of ' + ID.formatBytes(init.total_bytes));
              });
          });
        })(i);
      }
      return chain.then(function () { return new Blob(parts, { type: init.mime_type || 'application/octet-stream' }); });
    });
  }

  // -------------------------------------------------------------------------
  // Uploads
  // -------------------------------------------------------------------------
  var queue = [];
  var activeUploads = 0;
  var refreshTimer = null;
  var completedFolders = new Set();

  function pickFiles(folder) {
    if (!CAN_WRITE) return;
    var input = document.getElementById(folder ? 'folder-upload-input' : 'file-upload-input');
    if (input) input.click();
  }

  document.addEventListener('change', function (e) {
    if (e.target.id !== 'file-upload-input' && e.target.id !== 'folder-upload-input') return;
    var files = Array.prototype.slice.call(e.target.files || []);
    e.target.value = '';
    enqueue(files.map(function (f) { return { file: f, rel: f.webkitRelativePath || f.name }; }));
  });

  /** entries: [{ file: File, rel: 'sub/dir/name.txt' }] */
  function enqueue(entries) {
    if (!entries.length || !CAN_WRITE) return;
    var dir = currentPath();
    var existing = new Map(items().map(function (i) { return [nameOf(i), isDir(i)]; }));
    // Conflicts are checked on top-level names only; folder uploads merge.
    var clashes = entries.filter(function (en) {
      return en.rel.indexOf('/') === -1 && existing.has(en.rel) && !existing.get(en.rel);
    });
    var go = function (mode) {
      entries.forEach(function (en) {
        var rel = en.rel;
        if (mode === 'keep' && clashes.indexOf(en) !== -1) rel = uniqueName(rel);
        queue.push({ file: en.file, dest: joinPath(dir, rel), name: rel.split('/').pop(), dir: dir });
      });
      pump();
    };
    if (!clashes.length) { go('replace'); return; }

    var d = document.getElementById('conflict-dialog');
    document.getElementById('conflict-dialog-message').textContent = clashes.length === 1
      ? '“' + clashes[0].rel + '” already exists in this folder.'
      : plural(clashes.length, 'item') + ' already exist in this folder.';
    d.returnValue = '';
    ID.openDialog(d);
    d.addEventListener('close', function onClose() {
      d.removeEventListener('close', onClose);
      if (d.returnValue !== 'ok') return;
      go(d.querySelector('input[name=conflict]:checked').value);
    });
  }

  function pump() {
    while (activeUploads < MAX_PARALLEL_FILES && queue.length) startUpload(queue.shift());
  }

  function startUpload(job) {
    activeUploads++;
    var aborted = false;
    var xhrs = new Set();
    var uploadId = null;
    var t = ID.addTransfer({
      name: job.name,
      kind: 'upload',
      onCancel: function () {
        aborted = true;
        xhrs.forEach(function (x) { x.abort(); });
        if (uploadId) {
          ID.request(BASE + '/chunked/cancel?upload_id=' + encodeURIComponent(uploadId), { method: 'DELETE' }).catch(function () {});
        }
      },
    });
    var ctx = {
      t: t,
      track: function (x) { xhrs.add(x); },
      untrack: function (x) { xhrs.delete(x); },
      setUploadId: function (id) { uploadId = id; },
      isAborted: function () { return aborted; },
    };

    var run = job.file.size > CHUNK_SIZE ? uploadChunked(job, ctx) : uploadSingle(job, ctx);
    run.then(function () {
      t.done(ID.formatBytes(job.file.size));
      completedFolders.add(job.dir);
      scheduleRefresh();
    }).catch(function (err) {
      if (aborted) t.cancelled(); else t.fail(err.message);
    }).finally(function () {
      activeUploads--;
      pump();
    });
  }

  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () {
      // Only refresh if the user is still looking at a folder we uploaded into.
      if (completedFolders.has(currentPath()) || Array.from(completedFolders).some(function (d) { return parentOf(d) === currentPath(); })) {
        refresh(Array.from(selection));
      }
      if (!activeUploads && !queue.length) { completedFolders.clear(); ID.refreshUsage(); }
    }, activeUploads || queue.length ? 1500 : 250);
  }

  function xhrSend(method, url, body, ctx, onProgress) {
    return new Promise(function (resolve, reject) {
      if (ctx.isAborted()) { reject(new Error('Cancelled')); return; }
      var x = new XMLHttpRequest();
      ctx.track(x);
      x.open(method, url, true);
      x.setRequestHeader('X-CSRF-Token', ID.csrf());
      x.upload.addEventListener('progress', function (e) { if (e.lengthComputable && onProgress) onProgress(e.loaded); });
      x.addEventListener('load', function () {
        ctx.untrack(x);
        if (x.status >= 200 && x.status < 300) { resolve(x); return; }
        if (x.status === 401) window.location.href = '/login';
        var payload = null;
        try { payload = JSON.parse(x.responseText); } catch (_) { /* ignore */ }
        var err = new Error(ID.errorMessage(payload, 'Upload failed (' + x.status + ')'));
        err.status = x.status;
        reject(err);
      });
      x.addEventListener('error', function () { ctx.untrack(x); reject(new Error('Network error')); });
      x.addEventListener('abort', function () { ctx.untrack(x); reject(new Error('Cancelled')); });
      x.send(body);
    });
  }

  function uploadSingle(job, ctx) {
    var size = job.file.size;
    ctx.t.progress(0, 'Uploading…');
    return xhrSend('POST', BASE + '/upload?path=' + encodeURIComponent(job.dest), job.file, ctx, function (loaded) {
      ctx.t.progress(loaded / size, ID.formatBytes(loaded) + ' of ' + ID.formatBytes(size));
      if (loaded >= size) ctx.t.processing('Encrypting…');
    });
  }

  function uploadChunked(job, ctx) {
    var file = job.file;
    var total = Math.ceil(file.size / CHUNK_SIZE);
    var committed = 0;
    var inflight = {};
    var next = 0;
    ctx.t.progress(0, 'Starting…');

    function report() {
      var sent = committed;
      Object.keys(inflight).forEach(function (k) { sent += inflight[k]; });
      sent = Math.min(sent, file.size);
      ctx.t.progress(sent / file.size, ID.formatBytes(sent) + ' of ' + ID.formatBytes(file.size));
    }

    function sendChunk(idx, attempt) {
      var start = idx * CHUNK_SIZE;
      var blob = file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
      inflight[idx] = 0;
      return xhrSend('PUT', BASE + '/chunked/upload/' + encodeURIComponent(job.uploadId) + '/' + idx, blob, ctx, function (loaded) {
        inflight[idx] = loaded;
        report();
      }).then(function () {
        delete inflight[idx];
        committed += blob.size;
        report();
      }, function (err) {
        delete inflight[idx];
        // Retry transient failures (network / 5xx) with backoff.
        var transient = !err.status || err.status >= 500;
        if (transient && attempt < 3 && !ctx.isAborted()) {
          return new Promise(function (r) { setTimeout(r, 1000 * Math.pow(2, attempt)); })
            .then(function () { return sendChunk(idx, attempt + 1); });
        }
        throw err;
      });
    }

    function worker() {
      if (next >= total) return Promise.resolve();
      var idx = next++;
      return sendChunk(idx, 0).then(worker);
    }

    return ID.request(BASE + '/chunked/init', { method: 'POST', json: { path: job.dest, total_chunks: total, total_bytes: file.size } })
      .then(function (init) {
        job.uploadId = init.upload_id;
        ctx.setUploadId(init.upload_id);
        var workers = [];
        for (var i = 0; i < Math.min(MAX_PARALLEL_CHUNKS, total); i++) workers.push(worker());
        return Promise.all(workers);
      })
      .then(function () {
        ctx.t.processing('Encrypting…');
        return ID.request(BASE + '/chunked/complete', { method: 'POST', json: { upload_id: job.uploadId, verify: false } });
      })
      .catch(function (err) {
        if (job.uploadId && !ctx.isAborted()) {
          ID.request(BASE + '/chunked/cancel?upload_id=' + encodeURIComponent(job.uploadId), { method: 'DELETE' }).catch(function () {});
        }
        throw err;
      });
  }

  // Drag files/folders in from the desktop -------------------------------------
  var dropZone = document.getElementById('drop-zone');
  var dragDepth = 0;

  function isExternalFileDrag(e) {
    return !dragPaths && e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') !== -1;
  }

  function showDropZone(on) {
    if (!dropZone) return;
    dropZone.classList.toggle('hidden', !on);
    dropZone.classList.toggle('flex', on);
  }

  document.addEventListener('dragenter', function (e) {
    if (!isExternalFileDrag(e) || !CAN_WRITE) return;
    e.preventDefault();
    if (++dragDepth === 1) showDropZone(true);
  });
  document.addEventListener('dragleave', function (e) {
    if (!isExternalFileDrag(e) || !CAN_WRITE) return;
    if (--dragDepth <= 0) { dragDepth = 0; showDropZone(false); }
  });
  document.addEventListener('dragover', function (e) {
    if (isExternalFileDrag(e) && CAN_WRITE) e.preventDefault();
  });
  document.addEventListener('drop', function (e) {
    if (!isExternalFileDrag(e)) return;
    e.preventDefault();
    dragDepth = 0;
    showDropZone(false);
    if (!CAN_WRITE) { ID.toast('You have view-only access here.', { error: true }); return; }
    collectDropped(e.dataTransfer).then(enqueue);
  });

  /** Walk dropped files *and folders* into [{ file, rel }]. */
  function collectDropped(dt) {
    var roots = Array.prototype.map.call(dt.items || [], function (it) {
      return it.kind === 'file' && it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
    }).filter(Boolean);
    if (!roots.length) {
      return Promise.resolve(Array.prototype.map.call(dt.files || [], function (f) { return { file: f, rel: f.name }; }));
    }
    var out = [];
    function walk(entry, prefix) {
      if (entry.isFile) {
        return new Promise(function (resolve) {
          entry.file(function (f) { out.push({ file: f, rel: prefix + f.name }); resolve(); }, function () { resolve(); });
        });
      }
      if (!entry.isDirectory) return Promise.resolve();
      var reader = entry.createReader();
      var children = [];
      return new Promise(function (resolve) {
        // readEntries returns results in batches; call until empty.
        (function readBatch() {
          reader.readEntries(function (batch) {
            if (!batch.length) {
              Promise.all(children.map(function (c) { return walk(c, prefix + entry.name + '/'); })).then(resolve);
              return;
            }
            children.push.apply(children, batch);
            readBatch();
          }, function () { resolve(); });
        })();
      });
    }
    return Promise.all(roots.map(function (r) { return walk(r, ''); })).then(function () { return out; });
  }

  // -------------------------------------------------------------------------
  // Details panel
  // -------------------------------------------------------------------------
  var detailsPanel = document.getElementById('details');
  var detailsBody = document.getElementById('details-body');
  var detailsTitle = document.getElementById('details-title');
  var detailsCache = new Map();
  var detailsTimer = null;
  var detailsSeq = 0;
  var detailsOpen = false;
  try { detailsOpen = localStorage.getItem('irondrive-details') === 'open'; } catch (_) { /* ignore */ }
  // On small screens the panel is an overlay, so never start it open there.
  if (!window.matchMedia('(min-width: 1024px)').matches) detailsOpen = false;

  function syncDetailsToggle() {
    if (detailsPanel) detailsPanel.hidden = !detailsOpen;
    document.querySelectorAll('[data-details-toggle]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(detailsOpen));
    });
  }

  function setDetailsOpen(open) {
    detailsOpen = open;
    try { localStorage.setItem('irondrive-details', open ? 'open' : 'closed'); } catch (_) { /* ignore */ }
    syncDetailsToggle();
    if (open) updateDetails(true);
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-details-toggle]')) { setDetailsOpen(!detailsOpen); return; }
    if (e.target.closest('[data-details-close]')) setDetailsOpen(false);
  });

  function updateDetails(immediate) {
    if (!detailsOpen || !detailsBody) return;
    clearTimeout(detailsTimer);
    detailsTimer = setTimeout(renderDetails, immediate ? 0 : 120);
  }

  function row(label, value) {
    var d = ID.el('div', 'details-row');
    d.appendChild(ID.el('dt', '', label));
    var dd = ID.el('dd');
    if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
    d.appendChild(dd);
    return d;
  }

  function hero(glyph, kind, filled) {
    var box = ID.el('div', 'flex items-center justify-center h-40 rounded-xl bg-surface-2 mb-5');
    var ic = ID.icon(glyph, 'kind-' + kind + (filled ? ' ms-fill' : ''));
    ic.style.fontSize = '72px';
    box.appendChild(ic);
    return box;
  }

  function placeholder(text) {
    detailsTitle.textContent = 'Details';
    var wrap = ID.el('div', 'flex flex-col items-center text-center pt-10');
    var ic = ID.icon('info', 'text-subtle');
    ic.style.fontSize = '56px';
    wrap.appendChild(ic);
    wrap.appendChild(ID.el('p', 'mt-4 text-muted', text));
    detailsBody.replaceChildren(wrap);
  }

  function renderDetails() {
    var sel = selectedItems();
    if (sel.length > 1) {
      var files = sel.filter(function (i) { return !isDir(i); });
      var bytes = files.reduce(function (n, i) { return n + (+i.getAttribute('data-size') || 0); }, 0);
      detailsTitle.textContent = plural(sel.length, 'item') + ' selected';
      var dl = ID.el('dl', 'divide-y divide-outline/70');
      dl.appendChild(row('Files', String(files.length)));
      dl.appendChild(row('Folders', String(sel.length - files.length)));
      dl.appendChild(row('Size of selected files', ID.formatBytes(bytes)));
      detailsBody.replaceChildren(hero('select_all', 'file', false), dl);
      return;
    }
    var path = sel.length ? pathOf(sel[0]) : currentPath();
    if (!path) { placeholder('Select a file or folder to see its details.'); return; }

    var mine = ++detailsSeq;
    var cached = detailsCache.get(path);
    var load = cached ? Promise.resolve(cached) : ID.request(BASE + '/info?path=' + encodeURIComponent(path));
    if (!cached) detailsBody.replaceChildren(ID.el('p', 'pt-6 text-muted', 'Loading…'));
    load.then(function (info) {
      detailsCache.set(path, info);
      if (mine !== detailsSeq) return;
      renderInfo(info, !sel.length);
    }).catch(function (err) {
      if (mine !== detailsSeq) return;
      placeholder(err.message);
    });
  }

  function renderInfo(info, isCurrentFolder) {
    detailsTitle.textContent = info.name;
    detailsTitle.title = info.name;
    var nodes = [hero(info.glyph, info.icon, info.is_dir)];
    if (isCurrentFolder) nodes.push(ID.el('p', 'text-xs text-muted -mt-2 mb-3', 'This folder'));

    if (info.problems && info.problems.length) {
      var box = ID.el('div', 'mb-4 p-3 rounded-xl bg-danger-container text-on-danger-container');
      var head = ID.el('p', 'flex items-center gap-2 font-medium');
      head.appendChild(ID.icon('error', 'ms-fill'));
      head.appendChild(document.createTextNode(info.is_dir
        ? plural(info.problems.length, 'damaged file') + ' inside'
        : info.problems[0].title));
      box.appendChild(head);
      if (info.is_dir) {
        var ul = ID.el('ul', 'mt-2 space-y-1 text-[13px]');
        info.problems.slice(0, 5).forEach(function (p) { ul.appendChild(ID.el('li', 'truncate', p.file_path)); });
        box.appendChild(ul);
      } else {
        box.appendChild(ID.el('p', 'mt-1 text-[13px]', 'Restore it from a backup, or delete it.'));
      }
      nodes.push(box);
    }

    var dl = ID.el('dl', 'divide-y divide-outline/70');
    dl.appendChild(row('Type', info.type));
    if (info.is_dir && info.contents) {
      dl.appendChild(row('Contains', plural(info.contents.files, 'file') + ', ' + plural(info.contents.folders, 'folder')));
      dl.appendChild(row('Size on disk', info.contents.disk_size));
    } else {
      dl.appendChild(row('Size', info.size || '—'));
      if (info.disk_size) dl.appendChild(row('Size on disk (encrypted)', info.disk_size));
    }
    dl.appendChild(row('Location', info.location));
    if (info.modified) {
      var t = ID.el('time', '', info.modified);
      t.setAttribute('datetime', info.modified);
      t.setAttribute('data-full', '');
      dl.appendChild(row('Modified', t));
    }
    if (info.mime_type) dl.appendChild(row('Media type', info.mime_type));
    nodes.push(dl);

    if (!info.is_dir) {
      var check = ID.el('button', 'btn-outline w-full mt-5');
      check.type = 'button';
      check.appendChild(ID.icon('verified_user'));
      check.appendChild(document.createTextNode('Check integrity'));
      check.addEventListener('click', function () { verifyFile(info.path, check); });
      nodes.push(check);
      nodes.push(ID.el('p', 'mt-2 text-xs text-muted', 'Reads and decrypts the whole file to confirm nothing on disk is damaged.'));
    }

    detailsBody.replaceChildren.apply(detailsBody, nodes);
    ID.localizeTimes(detailsBody);
  }

  function verifyFile(path, btn) {
    btn.disabled = true;
    var label = btn.lastChild;
    label.textContent = 'Checking…';
    ID.request(BASE + '/verify?path=' + encodeURIComponent(path), { method: 'POST' }).then(function (res) {
      ID.toast(res.message, { error: !res.ok });
      detailsCache.delete(path);
      if (!res.ok || res.resolved) { ID.refreshAlerts(); refresh([path]); } else updateDetails(true);
    }).catch(function (err) {
      ID.toast(err.message, { error: true });
    }).finally(function () {
      btn.disabled = false;
      label.textContent = 'Check integrity';
    });
  }

  // -------------------------------------------------------------------------
  // Rubber-band selection: drag on empty space to select a rectangle
  // -------------------------------------------------------------------------
  var band = null;
  var suppressClick = false;

  browser.addEventListener('mousedown', function (e) {
    if (e.button !== 0 || coarsePointer.matches) return;
    if (e.target.closest('.item, a, button, input, label, .listing-head, #selection-bar, nav, dialog, .menu')) return;
    if (!items().length) return;
    var rect = browser.getBoundingClientRect();
    band = {
      x0: e.clientX - rect.left + browser.scrollLeft,
      y0: e.clientY - rect.top + browser.scrollTop,
      base: (e.ctrlKey || e.metaKey || e.shiftKey) ? new Set(selection) : new Set(),
      el: null,
      lastX: e.clientX,
      lastY: e.clientY,
      timer: null,
    };
    e.preventDefault(); // no text selection while dragging
  });

  function bandUpdate() {
    if (!band) return;
    var rect = browser.getBoundingClientRect();
    var x1 = band.lastX - rect.left + browser.scrollLeft;
    var y1 = band.lastY - rect.top + browser.scrollTop;
    var left = Math.min(band.x0, x1);
    var top = Math.min(band.y0, y1);
    var w = Math.abs(x1 - band.x0);
    var h = Math.abs(y1 - band.y0);
    if (!band.el) {
      if (w < 5 && h < 5) return; // still a click, not a drag
      band.el = ID.el('div', 'rubber-band');
      browser.appendChild(band.el);
    }
    band.el.style.left = left + 'px';
    band.el.style.top = top + 'px';
    band.el.style.width = w + 'px';
    band.el.style.height = h + 'px';

    // Compare in viewport coordinates.
    var vx0 = left - browser.scrollLeft + rect.left;
    var vy0 = top - browser.scrollTop + rect.top;
    var vx1 = vx0 + w;
    var vy1 = vy0 + h;
    selection = new Set(band.base);
    visibleItems().forEach(function (i) {
      var r = i.getBoundingClientRect();
      if (r.right > vx0 && r.left < vx1 && r.bottom > vy0 && r.top < vy1) selection.add(pathOf(i));
    });
    renderSelection();
  }

  // Auto-scroll while dragging near the top/bottom edge.
  function bandAutoScroll() {
    if (!band || !band.el) return;
    var rect = browser.getBoundingClientRect();
    var edge = 40;
    var dy = band.lastY < rect.top + edge + 64 ? -12 : band.lastY > rect.bottom - edge ? 12 : 0;
    if (dy) { browser.scrollTop += dy; bandUpdate(); }
  }

  document.addEventListener('mousemove', function (e) {
    if (!band) return;
    band.lastX = e.clientX;
    band.lastY = e.clientY;
    bandUpdate();
    if (!band.timer) band.timer = setInterval(bandAutoScroll, 30);
  });

  document.addEventListener('mouseup', function () {
    if (!band) return;
    clearInterval(band.timer);
    if (band.el) {
      band.el.remove();
      suppressClick = true; // the click that follows mouseup must not clear the selection
      setTimeout(function () { suppressClick = false; }, 0);
    }
    band = null;
  });

  // -------------------------------------------------------------------------
  // "New" menu + empty-state buttons
  // -------------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-action]');
    if (!b) return;
    var a = b.getAttribute('data-action');
    if (a === 'new-folder') { ID.closeMenus(); openNewFolder(); }
    else if (a === 'upload-files') { ID.closeMenus(); pickFiles(false); }
    else if (a === 'upload-folder') { ID.closeMenus(); pickFiles(true); }
  });

  // ?new=folder|files|folder-upload from the New menu on other pages.
  (function handleNewParam() {
    var params = new URLSearchParams(window.location.search);
    var what = params.get('new');
    if (!what) return;
    params.delete('new');
    var qs = params.toString();
    history.replaceState(history.state, '', window.location.pathname + (qs ? '?' + qs : ''));
    if (!CAN_WRITE) return;
    if (what === 'folder') { openNewFolder(); return; }
    // File pickers need a user gesture, so offer a one-click action.
    var folder = what === 'folder-upload';
    ID.toast(folder ? 'Choose a folder to upload' : 'Choose files to upload', {
      timeout: 10000,
      action: { label: 'Choose…', onClick: function () { pickFiles(folder); } },
    });
  })();

  onListingSwapped();
})();
