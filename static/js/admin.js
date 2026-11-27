// IronDrive – admin.js: quota dialog, password reset codes and "scan now" on the admin page.
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

  // Reset password: create a one-time code and show it once.
  var resetDialog = document.getElementById('reset-dialog');
  var resetUser = null;
  var EXPLAIN = {
    server: 'They choose a new password with a one-time code from you.',
    failsafe_user: 'They choose a new password with a one-time code from you, and their encryption keys are recovered from the server\u2019s recovery copy. This is logged and they are told.',
    pure_user: 'They choose a new login password with a one-time code from you. Their encryption password is separate and stays the same.'
  };
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-reset-user]');
    if (!b || !resetDialog) return;
    resetUser = b.getAttribute('data-reset-user');
    resetDialog.querySelectorAll('[data-reset-for]').forEach(function (s) { s.textContent = b.getAttribute('data-reset-name'); });
    resetDialog.querySelector('[data-reset-explain]').textContent = EXPLAIN[b.getAttribute('data-reset-tier')] || EXPLAIN.server;
    resetDialog.querySelector('[data-reset-form]').hidden = false;
    resetDialog.querySelector('[data-reset-result]').hidden = true;
    resetDialog.querySelector('[data-reset-form]').reset();
    ID.openDialog(resetDialog);
  });
  if (resetDialog) {
    resetDialog.querySelector('[data-reset-form]').addEventListener('submit', function (e) {
      e.preventDefault();
      var form = e.target;
      var btn = form.querySelector('[type=submit]');
      btn.disabled = true;
      ID.request('/admin/users/' + encodeURIComponent(resetUser) + '/reset', {
        method: 'POST', json: { reason: form.elements.reason.value }
      }).then(function (res) {
        form.hidden = true;
        var out = resetDialog.querySelector('[data-reset-result]');
        out.querySelector('[data-reset-code]').textContent = res.code;
        out.querySelector('[data-reset-url]').textContent = window.location.origin + '/reset';
        out.querySelector('[data-reset-note]').textContent = res.needs_encryption_password
          ? 'They use two passwords, so they\u2019ll also choose a new encryption password.'
          : '';
        out.hidden = false;
      }).catch(function (err) {
        ID.dialogError(resetDialog, err.message);
      }).then(function () { btn.disabled = false; });
    });
  }

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
