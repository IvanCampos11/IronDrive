// IronDrive – picker.js
// Typeahead for choosing a user (and optionally a group), used by "Add member"
// and "Share" dialogs. Markup: templates/partials/picker.html.tera.
//
// The surrounding <form data-picker-form> holds hidden inputs marked
// data-picker-value="name|id|type" that receive the chosen result, and a
// [data-picker-submit] button that is enabled once something is chosen.
(function () {
  'use strict';

  var ID = window.IronDrive;

  document.querySelectorAll('[data-picker]').forEach(function (picker) {
    var form = picker.closest('[data-picker-form]');
    var input = picker.querySelector('input[role=combobox]');
    var search = picker.querySelector('[data-picker-search]');
    var chosen = picker.querySelector('[data-picker-chosen]');
    var results = picker.querySelector('[role=listbox]');
    var types = (picker.getAttribute('data-picker-types') || 'user').split(',');
    var submit = form && form.querySelector('[data-picker-submit]');
    var timer = null;
    var active = -1;
    var current = [];
    var seq = 0;

    function setValue(item) {
      if (!form) return;
      form.querySelectorAll('[data-picker-value]').forEach(function (h) {
        h.value = item ? item[h.getAttribute('data-picker-value')] || '' : '';
      });
      if (submit) submit.disabled = !item;
    }

    function close() {
      results.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      active = -1;
    }

    function choose(item) {
      setValue(item);
      picker.querySelector('[data-picker-label]').textContent = item.name;
      var avatar = picker.querySelector('[data-picker-avatar]');
      avatar.replaceChildren(item.type === 'group' ? ID.icon('group', 'text-[16px]') : document.createTextNode(item.name.charAt(0).toUpperCase()));
      avatar.classList.toggle('bg-surface-3', item.type === 'group');
      avatar.classList.toggle('text-fg', item.type === 'group');
      search.hidden = true;
      chosen.classList.remove('hidden');
      chosen.classList.add('flex');
      close();
      if (submit) submit.focus();
    }

    function reset() {
      setValue(null);
      input.value = '';
      search.hidden = false;
      chosen.classList.add('hidden');
      chosen.classList.remove('flex');
      close();
    }

    function render(items, q) {
      current = items;
      results.replaceChildren();
      if (!items.length) {
        results.appendChild(ID.el('li', 'px-4 py-2 text-muted', 'No matches for “' + q + '”'));
      }
      items.forEach(function (item, i) {
        var li = ID.el('li', 'flex items-center gap-3 h-11 px-4 cursor-pointer hover:bg-fg/[0.06]');
        li.id = 'picker-opt-' + i;
        li.setAttribute('role', 'option');
        var avatar = ID.el('span', 'avatar w-7 h-7 text-xs' + (item.type === 'group' ? ' bg-surface-3 text-fg' : ''));
        if (item.type === 'group') avatar.appendChild(ID.icon('group', 'text-[16px]'));
        else avatar.textContent = item.name.charAt(0).toUpperCase();
        li.appendChild(avatar);
        li.appendChild(ID.el('span', 'flex-1 truncate', item.name));
        if (types.length > 1) li.appendChild(ID.el('span', 'text-xs text-muted', item.type === 'group' ? 'Group' : 'Person'));
        li.addEventListener('mousedown', function (e) { e.preventDefault(); choose(item); });
        results.appendChild(li);
      });
      results.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      highlight(items.length ? 0 : -1);
    }

    function highlight(i) {
      active = i;
      Array.prototype.forEach.call(results.children, function (li, k) {
        li.classList.toggle('bg-fg/[0.06]', k === i);
        li.setAttribute('aria-selected', String(k === i));
      });
      if (i >= 0 && results.children[i]) {
        input.setAttribute('aria-activedescendant', results.children[i].id);
        results.children[i].scrollIntoView({ block: 'nearest' });
      } else {
        input.removeAttribute('aria-activedescendant');
      }
    }

    input.addEventListener('input', function () {
      var q = input.value.trim();
      clearTimeout(timer);
      if (!q) { close(); return; }
      timer = setTimeout(function () {
        var mine = ++seq;
        ID.request('/search/grantees?q=' + encodeURIComponent(q)).then(function (data) {
          if (mine !== seq) return; // a newer search is in flight
          render((data.results || []).filter(function (r) { return types.indexOf(r.type) !== -1; }), q);
        }).catch(function () { close(); });
      }, 200);
    });

    input.addEventListener('keydown', function (e) {
      if (results.hidden) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); highlight(Math.min(active + 1, current.length - 1)); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); highlight(Math.max(active - 1, 0)); }
      else if (e.key === 'Enter') { e.preventDefault(); if (current[active]) choose(current[active]); }
      else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    });
    input.addEventListener('blur', function () { setTimeout(close, 100); });

    picker.querySelector('[data-picker-clear]').addEventListener('click', function () { reset(); input.focus(); });

    var dialog = picker.closest('dialog');
    if (dialog) dialog.addEventListener('close', reset);
  });
})();
