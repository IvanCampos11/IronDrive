// IronDrive – core.js
// Shared UI runtime loaded on every page: requests, snackbars, dialogs,
// menus, the transfers panel, theme/sidebar toggles and small helpers.
// Exposes window.IronDrive for page scripts (browser.js, spaces.js, …).
(function () {
  'use strict';

  var root = document.documentElement;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------
  function csrf() {
    var m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function formatBytes(n) {
    if (!Number.isFinite(n)) return '';
    if (n < 1024) return n + ' B';
    var units = ['KB', 'MB', 'GB', 'TB'];
    var v = n;
    var i = -1;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
  }

  function errorMessage(payload, fallback) {
    if (!payload) return fallback;
    if (typeof payload === 'string') return payload;
    if (typeof payload.error === 'string') return payload.error;
    if (payload.error && payload.error.description) return payload.error.description;
    if (Array.isArray(payload.errors) && payload.errors.length) return payload.errors[0];
    if (typeof payload.message === 'string') return payload.message;
    return fallback;
  }

  /**
   * fetch() wrapper: sends the CSRF header, encodes `json`, parses JSON
   * responses, and throws Error(message) for non-2xx responses. A 401 sends
   * the user back to the sign-in page.
   */
  function request(url, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'X-CSRF-Token': csrf(), Accept: 'application/json' }, opts.headers || {});
    var body = opts.body;
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.json);
    }
    return fetch(url, { method: opts.method || 'GET', headers: headers, body: body, credentials: 'same-origin' })
      .then(function (resp) {
        if (resp.status === 401) {
          window.location.href = '/login';
          throw new Error('Your session has expired.');
        }
        // Locked (423): the keys went away (server restart, sign-out
        // elsewhere, space locked). Reloading lands on the unlock prompt.
        if (resp.status === 423) {
          window.location.reload();
          throw new Error('This is locked. Unlock it to continue.');
        }
        return resp.text().then(function (txt) {
          var payload = null;
          try { payload = txt ? JSON.parse(txt) : null; } catch (_) { payload = null; }
          if (!resp.ok) throw new Error(errorMessage(payload, 'Something went wrong (' + resp.status + ').'));
          return payload || {};
        });
      }, function () {
        throw new Error('Network error — check your connection.');
      });
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function icon(name, extra) {
    return el('span', 'ms' + (extra ? ' ' + extra : ''), name);
  }

  // -------------------------------------------------------------------------
  // Dates: render <time datetime> in the viewer's locale and timezone
  // -------------------------------------------------------------------------
  var fmtTime = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
  var fmtDay = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
  var fmtFull = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  var fmtTitle = new Intl.DateTimeFormat(undefined, { dateStyle: 'full', timeStyle: 'short' });

  function friendlyDate(d) {
    var now = new Date();
    if (d.toDateString() === now.toDateString()) return fmtTime.format(d);
    if (d.getFullYear() === now.getFullYear()) return fmtDay.format(d);
    return fmtFull.format(d);
  }

  function localizeTimes(scope) {
    (scope || document).querySelectorAll('time[datetime]').forEach(function (t) {
      var raw = t.getAttribute('datetime');
      if (!raw) return;
      // Server timestamps without a zone are UTC.
      var d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : raw.replace(' ', 'T') + 'Z');
      if (isNaN(d)) return;
      t.textContent = t.hasAttribute('data-full') ? fmtFull.format(d) : friendlyDate(d);
      t.title = fmtTitle.format(d);
    });
  }

  // -------------------------------------------------------------------------
  // Snackbars
  // -------------------------------------------------------------------------
  function dismissSnack(s) {
    if (!s || !s.parentNode) return;
    s.style.transition = 'opacity 150ms';
    s.style.opacity = '0';
    setTimeout(function () { s.remove(); }, 160);
  }

  function armSnack(s, ms) {
    setTimeout(function () { dismissSnack(s); }, ms || 5000);
  }

  /** toast('Folder created') / toast('Failed', { error: true, action: { label, onClick } }) */
  function toast(message, opts) {
    opts = opts || {};
    var host = document.getElementById('snackbars');
    if (!host) return;
    // Keep at most 3 on screen.
    while (host.children.length >= 3) host.firstElementChild.remove();
    var s = el('div', 'snackbar');
    s.setAttribute('role', opts.error ? 'alert' : 'status');
    if (opts.error) s.appendChild(icon('error', 'text-[#ffb4ab] dark:text-danger'));
    s.appendChild(el('span', 'flex-1 py-1', message));
    if (opts.action) {
      var a = el('button', 'btn-text btn-sm text-[#a8c2ff] dark:text-primary', opts.action.label);
      a.type = 'button';
      a.addEventListener('click', function () { dismissSnack(s); opts.action.onClick(); });
      s.appendChild(a);
    }
    var close = el('button', 'icon-btn-sm');
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss');
    close.appendChild(icon('close'));
    close.addEventListener('click', function () { dismissSnack(s); });
    s.appendChild(close);
    host.appendChild(s);
    armSnack(s, opts.timeout || (opts.error ? 8000 : 4000));
    return s;
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-dismiss-snackbar]');
    if (b) dismissSnack(b.closest('.snackbar'));
  });

  // -------------------------------------------------------------------------
  // Dialogs (native <dialog>)
  // -------------------------------------------------------------------------
  function openDialog(d) {
    if (typeof d === 'string') d = document.getElementById(d);
    if (!d || d.open) return d;
    closeMenus();
    d.querySelectorAll('[data-error]').forEach(function (x) { x.hidden = true; });
    d.showModal();
    var focus = d.querySelector('[autofocus], input:not([type=hidden]):not([type=radio]), textarea, select');
    if (focus) {
      focus.focus();
      if (focus.select && focus.type === 'text') focus.select();
    }
    return d;
  }

  function closeDialog(d) {
    if (typeof d === 'string') d = document.getElementById(d);
    if (d && d.open) d.close();
  }

  function dialogError(d, msg) {
    var e = d && d.querySelector('[data-error]');
    if (!e) { toast(msg, { error: true }); return; }
    e.textContent = msg;
    e.hidden = false;
  }

  document.addEventListener('click', function (e) {
    var opener = e.target.closest('[data-dialog-open]');
    if (opener) { e.preventDefault(); openDialog(opener.getAttribute('data-dialog-open')); return; }
    var closer = e.target.closest('dialog [data-close]');
    if (closer) { closeDialog(closer.closest('dialog')); return; }
    // Click on the backdrop (outside the dialog box) closes it.
    if (e.target.tagName === 'DIALOG' && e.target.open) {
      var r = e.target.getBoundingClientRect();
      var inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
      if (!inside) e.target.close('cancel');
    }
  });

  /** confirm({ title, message, confirmLabel, danger }) → Promise<boolean> */
  function confirmDialog(opts) {
    var d = document.getElementById('confirm-dialog');
    if (!d) return Promise.resolve(window.confirm(opts.message || opts.title));
    d.querySelector('#confirm-dialog-title').textContent = opts.title || 'Are you sure?';
    d.querySelector('#confirm-dialog-message').textContent = opts.message || '';
    var ok = d.querySelector('#confirm-dialog-ok');
    ok.textContent = opts.confirmLabel || 'OK';
    ok.className = opts.danger ? 'btn-text text-danger hover:bg-danger/10' : 'btn-text';
    d.returnValue = '';
    openDialog(d);
    ok.focus();
    return new Promise(function (resolve) {
      d.addEventListener('close', function onClose() {
        d.removeEventListener('close', onClose);
        resolve(d.returnValue === 'ok');
      });
    });
  }

  // Forms with data-confirm ask first: <form data-confirm="Remove Ana?" data-confirm-label="Remove">
  document.addEventListener('submit', function (e) {
    var form = e.target;
    var msg = form.getAttribute && form.getAttribute('data-confirm');
    if (!msg || form.dataset.confirmed === 'yes') return;
    e.preventDefault();
    confirmDialog({
      title: form.getAttribute('data-confirm-title') || 'Are you sure?',
      message: msg,
      confirmLabel: form.getAttribute('data-confirm-label') || 'OK',
      danger: form.hasAttribute('data-confirm-danger'),
    }).then(function (yes) {
      if (!yes) return;
      form.dataset.confirmed = 'yes';
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    });
  });

  // Prevent accidental double submission of classic (navigating) forms.
  // Registered on window so it runs after page handlers and can tell whether
  // they intercepted the submit.
  window.addEventListener('submit', function (e) {
    var form = e.target;
    if (e.defaultPrevented || form.method === 'dialog') return;
    if (form.dataset.submitting === 'yes') { e.preventDefault(); return; }
    form.dataset.submitting = 'yes';
    var btn = form.querySelector('button[type=submit], button:not([type])');
    if (btn) btn.disabled = true;
  });
  window.addEventListener('pageshow', function () {
    document.querySelectorAll('form[data-submitting]').forEach(function (f) {
      delete f.dataset.submitting;
      f.querySelectorAll('button').forEach(function (b) { b.disabled = false; });
    });
  });

  // -------------------------------------------------------------------------
  // Menus (popovers). Trigger: [data-menu-trigger="menu-id"].
  // -------------------------------------------------------------------------
  var openMenu = null;
  var openTrigger = null;

  function closeMenus() {
    if (openMenu && openMenu.id === 'alerts-menu' && alertsDirty) {
      alertsDirty = false;
      setTimeout(refreshAlerts, 0);
    }
    if (openMenu) openMenu.hidden = true;
    if (openTrigger) openTrigger.setAttribute('aria-expanded', 'false');
    openMenu = null;
    openTrigger = null;
  }

  /** Show `menu` next to `anchor` (an element) or at `point` ({x, y}). */
  function showMenu(menu, anchor, point) {
    closeMenus();
    menu.hidden = false;
    menu.style.visibility = 'hidden';
    menu.style.left = '0px';
    menu.style.top = '0px';
    var w = menu.offsetWidth;
    var h = menu.offsetHeight;
    var vw = window.innerWidth;
    var vh = window.innerHeight;
    var x;
    var y;
    if (point) {
      x = point.x;
      y = point.y;
    } else {
      var r = anchor.getBoundingClientRect();
      // Align to the anchor's left edge, or its right edge if that fits better.
      x = r.left + w > vw - 8 ? r.right - w : r.left;
      y = r.bottom + 4;
      if (y + h > vh - 8 && r.top - h - 4 > 8) y = r.top - h - 4;
    }
    x = Math.max(8, Math.min(x, vw - w - 8));
    y = Math.max(8, Math.min(y, vh - h - 8));
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu.style.visibility = '';
    openMenu = menu;
    openTrigger = anchor || null;
    if (anchor) anchor.setAttribute('aria-expanded', 'true');
    var first = menu.querySelector('.menu-item');
    if (first && !point) first.focus({ preventScroll: true });
  }

  document.addEventListener('click', function (e) {
    var trigger = e.target.closest('[data-menu-trigger]');
    if (trigger) {
      var menu = document.getElementById(trigger.getAttribute('data-menu-trigger'));
      if (!menu) return;
      e.preventDefault();
      if (openMenu === menu) { closeMenus(); return; }
      showMenu(menu, trigger);
      return;
    }
    if (openMenu && !openMenu.contains(e.target)) { closeMenus(); return; }
    // Clicking an item closes the menu after its own handler runs.
    if (openMenu && e.target.closest('.menu-item')) setTimeout(closeMenus, 0);
  });

  document.addEventListener('keydown', function (e) {
    if (!openMenu) return;
    if (e.key === 'Escape') {
      var t = openTrigger;
      closeMenus();
      if (t) t.focus();
      e.preventDefault();
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      var items = Array.prototype.slice.call(openMenu.querySelectorAll('.menu-item'));
      if (!items.length) return;
      var i = items.indexOf(document.activeElement);
      i = e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
      items[i].focus();
      e.preventDefault();
    }
  });
  window.addEventListener('resize', closeMenus);
  document.addEventListener('scroll', closeMenus, true);

  // -------------------------------------------------------------------------
  // Integrity alerts (bell menu)
  // -------------------------------------------------------------------------
  var alertsDirty = false;

  function refreshAlerts() {
    if (window.htmx) window.htmx.trigger(document.body, 'alerts-refresh');
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-dismiss-alert]');
    if (!b) return;
    e.stopPropagation();
    var id = b.getAttribute('data-dismiss-alert');
    b.disabled = true;
    var url = b.getAttribute('data-dismiss-url') || '/notifications/' + encodeURIComponent(id) + '/dismiss';
    request(url, { method: 'POST' }).then(function () {
      var li = b.closest('[data-alert]');
      var list = li && li.parentNode;
      if (li) li.remove();
      // In the bell menu, refresh once it closes; elsewhere (admin page) right away.
      if (b.closest('#alerts-menu')) alertsDirty = true; else refreshAlerts();
      if (list && !list.children.length) { closeMenus(); }
    }).catch(function (err) {
      b.disabled = false;
      toast(err.message, { error: true });
    });
  });

  // Highlight the sidebar link for the current space / admin page.
  function markNav() {
    var path = window.location.pathname;
    document.querySelectorAll('[data-nav-space]').forEach(function (a) {
      var href = a.getAttribute('data-nav-space');
      if (path === href || path.indexOf(href + '/') === 0) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }
  document.addEventListener('htmx:afterSettle', markNav);

  // -------------------------------------------------------------------------
  // Theme + sidebar
  // -------------------------------------------------------------------------
  function store(key, val) { try { localStorage.setItem(key, val); } catch (_) { /* ignore */ } }

  document.addEventListener('click', function (e) {
    if (e.target.closest('#theme-toggle')) {
      store('irondrive-theme', root.classList.toggle('dark') ? 'dark' : 'light');
      return;
    }
    if (e.target.closest('#sidebar-toggle')) {
      if (window.matchMedia('(min-width: 1024px)').matches) {
        store('irondrive-sidebar', root.classList.toggle('sidebar-collapsed') ? 'collapsed' : 'open');
      } else {
        setDrawer(!root.classList.contains('sidebar-open'));
      }
      return;
    }
    if (e.target.closest('#sidebar-scrim')) setDrawer(false);
  });

  function setDrawer(open) {
    root.classList.toggle('sidebar-open', open);
    var scrim = document.getElementById('sidebar-scrim');
    if (scrim) scrim.hidden = !open;
  }

  // -------------------------------------------------------------------------
  // Transfers panel (uploads + downloads)
  // -------------------------------------------------------------------------
  var transfers = [];
  var nextTransferId = 1;

  function panel() { return document.getElementById('transfers'); }

  function updateTransfersHeader() {
    var p = panel();
    if (!p) return;
    var active = transfers.filter(function (t) { return t.state === 'active'; });
    var failed = transfers.filter(function (t) { return t.state === 'failed'; });
    var done = transfers.filter(function (t) { return t.state === 'done'; });
    var title;
    if (active.length) {
      var ups = active.filter(function (t) { return t.kind === 'upload'; }).length;
      title = ups === active.length
        ? 'Uploading ' + ups + ' item' + (ups === 1 ? '' : 's')
        : (ups === 0 ? 'Downloading ' : 'Transferring ') + active.length + ' item' + (active.length === 1 ? '' : 's');
    } else if (failed.length) {
      title = failed.length + ' transfer' + (failed.length === 1 ? '' : 's') + ' failed';
    } else {
      var upsDone = done.filter(function (t) { return t.kind === 'upload'; }).length;
      title = upsDone === done.length
        ? done.length + ' upload' + (done.length === 1 ? '' : 's') + ' complete'
        : done.length + ' transfer' + (done.length === 1 ? '' : 's') + ' complete';
    }
    document.getElementById('transfers-title').textContent = title;
  }

  /**
   * addTransfer({ name, kind: 'upload'|'download', onCancel }) → handle with
   * progress(fraction, text), processing(text), done(), fail(message).
   */
  function addTransfer(opts) {
    var p = panel();
    var t = { id: nextTransferId++, kind: opts.kind, state: 'active', onCancel: opts.onCancel };
    transfers.push(t);
    if (!p) return makeHandle(t, null);

    var li = el('li', 'flex items-center gap-3 h-14 pl-5 pr-2 hover:bg-fg/[0.04]');
    li.appendChild(icon(opts.kind === 'upload' ? 'upload' : 'download', 'text-muted'));
    var mid = el('div', 'flex-1 min-w-0');
    var name = el('p', 'truncate', opts.name);
    name.title = opts.name;
    var bar = el('div', 'progress mt-1.5');
    var fill = el('span');
    fill.style.width = '0%';
    bar.appendChild(fill);
    var status = el('p', 'text-xs text-muted mt-1 truncate', opts.kind === 'upload' ? 'Waiting…' : 'Starting…');
    mid.appendChild(name);
    mid.appendChild(bar);
    mid.appendChild(status);
    li.appendChild(mid);
    var action = el('button', 'icon-btn-sm');
    action.type = 'button';
    action.setAttribute('aria-label', 'Cancel');
    action.title = 'Cancel';
    action.appendChild(icon('cancel'));
    action.addEventListener('click', function () {
      if (t.state === 'active' && t.onCancel) t.onCancel();
    });
    if (!opts.onCancel) action.style.visibility = 'hidden';
    li.appendChild(action);
    document.getElementById('transfers-list').appendChild(li);
    p.hidden = false;
    t.dom = { li: li, bar: bar, fill: fill, status: status, action: action };
    updateTransfersHeader();
    return makeHandle(t, t.dom);
  }

  function makeHandle(t, dom) {
    function finish(state, text, iconName, cls) {
      t.state = state;
      if (dom) {
        dom.bar.remove();
        dom.status.textContent = text;
        dom.status.className = 'text-xs mt-0.5 truncate ' + (state === 'failed' ? 'text-danger' : 'text-muted');
        dom.action.style.visibility = 'visible';
        dom.action.replaceChildren(icon(iconName, cls));
        dom.action.disabled = true;
        dom.action.removeAttribute('title');
        dom.action.setAttribute('aria-label', text);
      }
      updateTransfersHeader();
    }
    return {
      progress: function (fraction, text) {
        if (!dom || t.state !== 'active') return;
        dom.bar.classList.remove('progress-indeterminate');
        dom.fill.style.width = Math.max(0, Math.min(100, fraction * 100)) + '%';
        if (text) dom.status.textContent = text;
      },
      processing: function (text) {
        if (!dom || t.state !== 'active') return;
        dom.bar.classList.add('progress-indeterminate');
        dom.status.textContent = text;
      },
      done: function (text) { finish('done', text || 'Done', 'check_circle', 'ms-fill text-success'); },
      fail: function (msg) { finish('failed', msg || 'Failed', 'error', 'ms-fill text-danger'); },
      cancelled: function () { finish('cancelled', 'Cancelled', 'cancel', 'text-muted'); },
      get state() { return t.state; },
    };
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('#transfers-collapse')) {
      var btn = document.getElementById('transfers-collapse');
      var list = document.getElementById('transfers-list');
      var expanded = btn.getAttribute('aria-expanded') !== 'false';
      list.hidden = expanded;
      btn.setAttribute('aria-expanded', String(!expanded));
      btn.querySelector('.ms').textContent = expanded ? 'expand_less' : 'expand_more';
      return;
    }
    if (e.target.closest('#transfers-close')) {
      var active = transfers.filter(function (t) { return t.state === 'active'; });
      var close = function () {
        active.forEach(function (t) { if (t.onCancel) t.onCancel(); });
        transfers = [];
        document.getElementById('transfers-list').replaceChildren();
        panel().hidden = true;
      };
      if (!active.length) { close(); return; }
      confirmDialog({
        title: 'Cancel transfers?',
        message: active.length + ' transfer' + (active.length === 1 ? ' is' : 's are') + ' still in progress.',
        confirmLabel: 'Cancel transfers',
        danger: true,
      }).then(function (yes) { if (yes) close(); });
    }
  });

  window.addEventListener('beforeunload', function (e) {
    if (transfers.some(function (t) { return t.state === 'active'; })) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  // -------------------------------------------------------------------------
  // HTMX integration
  // -------------------------------------------------------------------------
  var loadingBar = el('div', 'fixed top-0 inset-x-0 h-0.5 z-[70] progress-indeterminate overflow-hidden pointer-events-none');
  loadingBar.appendChild(el('span', 'block h-full bg-primary'));
  loadingBar.hidden = true;
  document.addEventListener('DOMContentLoaded', function () { document.body.appendChild(loadingBar); });

  var pending = 0;
  document.addEventListener('htmx:beforeRequest', function () { pending++; loadingBar.hidden = false; });
  document.addEventListener('htmx:afterRequest', function () {
    pending = Math.max(0, pending - 1);
    if (!pending) loadingBar.hidden = true;
  });
  document.addEventListener('htmx:responseError', function (e) {
    var status = e.detail.xhr && e.detail.xhr.status;
    if (status === 401) { window.location.href = '/login'; return; }
    if (status === 423) { window.location.reload(); return; }
    toast(status === 404 ? 'That folder no longer exists.' : 'Couldn’t load that — please try again.', { error: true });
  });
  document.addEventListener('htmx:sendError', function () {
    toast('Network error — check your connection.', { error: true });
  });
  document.addEventListener('htmx:afterSwap', function (e) { localizeTimes(e.detail.target); });

  // -------------------------------------------------------------------------
  // Conditional form sections
  // <form data-conditional> … <div data-show-if="tier=failsafe_user,pure_user">
  // shows the block only while the named radio/select has one of the values.
  // Hidden blocks' inputs are disabled so `required` doesn't block submit.
  // -------------------------------------------------------------------------
  function syncConditional(form) {
    form.querySelectorAll('[data-show-if]').forEach(function (block) {
      var rule = block.getAttribute('data-show-if').split('=');
      var allowed = (rule[1] || '').split(',');
      var field = form.querySelector('[name="' + rule[0] + '"]:checked') ||
        form.querySelector('select[name="' + rule[0] + '"]');
      var show = !!field && allowed.indexOf(field.value) >= 0;
      // A block inside a hidden block stays hidden.
      var parent = block.parentElement && block.parentElement.closest('[data-show-if]');
      if (parent && parent.hidden) show = false;
      block.hidden = !show;
    });
    form.querySelectorAll('[data-show-if] input, [data-show-if] select, [data-show-if] textarea').forEach(function (inp) {
      inp.disabled = !!inp.closest('[data-show-if][hidden]');
    });
  }
  document.addEventListener('change', function (e) {
    var form = e.target.closest && e.target.closest('form[data-conditional]');
    if (form) syncConditional(form);
  });

  // Matching "repeat password" fields: <input data-match="other_field_name">.
  document.addEventListener('submit', function (e) {
    var form = e.target;
    var bad = Array.prototype.find.call(form.querySelectorAll('input[data-match]:not(:disabled)'), function (inp) {
      var other = form.querySelector('[name="' + inp.getAttribute('data-match') + '"]');
      return other && other.value !== inp.value;
    });
    if (bad) {
      e.preventDefault();
      bad.setCustomValidity('The passwords don’t match.');
      bad.reportValidity();
      bad.addEventListener('input', function () { bad.setCustomValidity(''); }, { once: true });
    }
  }, true);

  // -------------------------------------------------------------------------
  // Page start
  // -------------------------------------------------------------------------
  function start() {
    localizeTimes(document);
    document.querySelectorAll('form[data-conditional]').forEach(syncConditional);
    document.querySelectorAll('.snackbar[data-auto-dismiss]').forEach(function (s) { armSnack(s, 5000); });

    // ?new=1 on index pages opens their "create" dialog (from the New menu).
    var params = new URLSearchParams(window.location.search);
    if (params.get('new') === '1') {
      var dlg = document.querySelector('dialog[data-new-dialog]');
      if (dlg) openDialog(dlg);
      params.delete('new');
      var qs = params.toString();
      history.replaceState(history.state, '', window.location.pathname + (qs ? '?' + qs : ''));
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();

  /** Re-fetch the sidebar storage bar after something changed usage. */
  function refreshUsage() {
    var box = document.getElementById('sidebar-usage');
    if (box && window.htmx) window.htmx.ajax('GET', '/usage/sidebar', { target: box, swap: 'innerHTML' });
  }

  window.IronDrive = {
    csrf: csrf,
    request: request,
    toast: toast,
    confirm: confirmDialog,
    openDialog: openDialog,
    closeDialog: closeDialog,
    dialogError: dialogError,
    showMenu: showMenu,
    closeMenus: closeMenus,
    addTransfer: addTransfer,
    formatBytes: formatBytes,
    localizeTimes: localizeTimes,
    el: el,
    icon: icon,
    errorMessage: errorMessage,
    refreshAlerts: refreshAlerts,
    refreshUsage: refreshUsage,
  };
})();
