// IronDrive – admin.js: quota dialog and "scan now" on the admin page.
(function () {
  'use strict';
  var ID = window.IronDrive;

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-quota-user]');
    if (!b) return;
    var d = document.getElementById('quota-dialog');
    var form = d.querySelector('form');
    form.action = '/admin/users/' + encodeURIComponent(b.getAttribute('data-quota-user')) + '/quota';
    d.querySelector('[data-quota-for]').textContent = b.getAttribute('data-quota-name');
    form.elements.quota.value = b.getAttribute('data-quota-value');
    ID.openDialog(d);
  });

  var scan = document.getElementById('admin-scan');
  if (scan) {
    scan.addEventListener('click', function () {
      scan.disabled = true;
      ID.request('/admin/scan', { method: 'POST' }).then(function (res) {
        ID.toast(res.message);
        scan.lastChild.textContent = 'Scan running…';
      }).catch(function (err) {
        scan.disabled = false;
        ID.toast(err.message, { error: true });
      });
    });
  }
})();
