// Trash page: select items, restore them, or delete them forever.
(function () {
  'use strict';
  var ID = window.IronDrive;
  var root = document.getElementById('trash');
  if (!root || !ID) return;
  // Only the two shapes the server renders: /trash or /spaces/<id>/trash.
  // Anything else is ignored rather than used to build request or link URLs.
  var m = /^\/(?:trash|spaces\/([A-Za-z0-9-]+)\/trash)$/.exec(root.getAttribute('data-base') || '');
  if (!m) return;
  var BASE = m[0];
  var HOME = m[1] ? '/spaces/' + encodeURIComponent(m[1]) : '/files';

  function rows() { return Array.prototype.slice.call(root.querySelectorAll('.trash-row')); }
  function selected() { return rows().filter(function (r) { return r.getAttribute('aria-selected') === 'true'; }); }
  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

  function setSelected(row, on) {
    row.setAttribute('aria-selected', on ? 'true' : 'false');
    row.querySelector('.check').checked = on;
  }

  function sync() {
    var sel = selected();
    var bar = document.getElementById('trash-selection');
    if (bar) bar.hidden = sel.length === 0;
    var count = document.getElementById('trash-count');
    if (count) count.textContent = sel.length + ' selected';
    var all = document.getElementById('trash-all');
    if (all) {
      all.checked = sel.length > 0 && sel.length === rows().length;
      all.indeterminate = sel.length > 0 && sel.length < rows().length;
    }
  }

  root.addEventListener('change', function (e) {
    if (e.target.id === 'trash-all') {
      rows().forEach(function (r) { setSelected(r, e.target.checked); });
    } else if (e.target.classList.contains('check')) {
      setSelected(e.target.closest('.trash-row'), e.target.checked);
    }
    sync();
  });

  // Clicking a row (not a button or checkbox) toggles it.
  root.addEventListener('click', function (e) {
    var row = e.target.closest('.trash-row');
    if (row && !e.target.closest('button, input')) {
      if (!(e.ctrlKey || e.metaKey || e.shiftKey)) rows().forEach(function (r) { if (r !== row) setSelected(r, false); });
      setSelected(row, row.getAttribute('aria-selected') !== 'true');
      sync();
      return;
    }
    var rowBtn = e.target.closest('[data-row]');
    if (rowBtn) {
      var r = rowBtn.closest('.trash-row');
      if (rowBtn.getAttribute('data-row') === 'restore') restore([r]); else deleteForever([r]);
      return;
    }
    var btn = e.target.closest('[data-trash]');
    if (!btn) return;
    var action = btn.getAttribute('data-trash');
    if (action === 'clear') { rows().forEach(function (x) { setSelected(x, false); }); sync(); }
    else if (action === 'restore') restore(selected());
    else if (action === 'delete') deleteForever(selected());
    else if (action === 'empty') emptyTrash();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && selected().length) { rows().forEach(function (x) { setSelected(x, false); }); sync(); }
  });

  function removeRows(list) {
    list.forEach(function (r) { r.classList.add('is-leaving'); });
    setTimeout(function () {
      list.forEach(function (r) { r.remove(); });
      sync();
      ID.refreshUsage();
      if (!rows().length) window.location.reload();
    }, 200);
  }

  function ids(list) { return list.map(function (r) { return r.getAttribute('data-id'); }); }

  function restore(list) {
    if (!list.length) return;
    ID.request(BASE + '/restore', { method: 'POST', json: { ids: ids(list) } }).then(function (res) {
      var done = res.restored || [];
      var doneIds = new Set(done.map(function (x) { return x.id; }));
      removeRows(list.filter(function (r) { return doneIds.has(r.getAttribute('data-id')); }));
      if ((res.errors || []).length) ID.toast(res.errors[0], { error: true });
      if (done.length === 1) {
        var path = done[0].path;
        var parent = path.indexOf('/') >= 0 ? path.slice(0, path.lastIndexOf('/')) : '';
        var folderUrl = HOME + (parent ? '?path=' + encodeURIComponent(parent) : '');
        ID.toast('“' + path.split('/').pop() + '” restored', {
          action: { label: 'Show', onClick: function () { window.location.href = folderUrl; } },
        });
      } else if (done.length) {
        ID.toast(plural(done.length, 'item') + ' restored');
      }
    }).catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  function deleteForever(list) {
    if (!list.length) return;
    var one = list.length === 1;
    ID.confirm({
      title: one ? 'Delete “' + list[0].getAttribute('data-name') + '” forever?' : 'Delete ' + plural(list.length, 'item') + ' forever?',
      message: 'You can’t undo this.',
      confirmLabel: 'Delete forever',
      danger: true,
    }).then(function (yes) {
      if (!yes) return;
      return ID.request(BASE + '/delete', { method: 'POST', json: { ids: ids(list) } }).then(function (res) {
        if ((res.errors || []).length) { ID.toast(res.errors[0], { error: true }); window.location.reload(); return; }
        removeRows(list);
        ID.toast(one ? 'Deleted forever' : plural(list.length, 'item') + ' deleted forever');
      });
    }).catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  function emptyTrash() {
    ID.confirm({
      title: 'Empty trash?',
      message: 'All ' + plural(rows().length, 'item') + ' in the trash will be deleted forever. You can’t undo this.',
      confirmLabel: 'Empty trash',
      danger: true,
    }).then(function (yes) {
      if (!yes) return;
      return ID.request(BASE + '/empty', { method: 'POST' }).then(function () { window.location.reload(); });
    }).catch(function (err) { ID.toast(err.message, { error: true }); });
  }

  sync();
})();
