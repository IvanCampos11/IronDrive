// IronDrive – app.js (vanilla JS, no frameworks)
(function () {
  'use strict';

  // -----------------------------------------------------------------------
  // CSRF helper — read csrf_token from cookie
  // -----------------------------------------------------------------------
  function getCsrfToken() {
    var match = document.cookie.match('(?:^|; )csrf_token=([^;]*)');
    return match ? decodeURIComponent(match[1]) : '';
  }

  function getChunkSizeBytes() {
    var root = document.getElementById('file-browser-content');
    if (!root) return 8 * 1024 * 1024;
    var raw = root.getAttribute('data-chunk-size-bytes');
    var parsed = parseInt(raw || '', 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 8 * 1024 * 1024;
    return parsed;
  }

  function parseErrorMessage(payload, fallback) {
    if (!payload) return fallback;
    if (typeof payload === 'string') return payload;
    if (payload.error && typeof payload.error === 'string') return payload.error;
    if (payload.error && payload.error.description) return payload.error.description;
    if (payload.message && typeof payload.message === 'string') return payload.message;
    return fallback;
  }

  function jsonFetch(url, options) {
    var opts = options || {};
    opts.headers = opts.headers || {};
    opts.headers['X-CSRF-Token'] = getCsrfToken();

    return fetch(url, opts).then(function (resp) {
      return resp.text().then(function (txt) {
        var payload = {};
        try {
          payload = txt ? JSON.parse(txt) : {};
        } catch (_) {
          payload = {};
        }
        if (!resp.ok) {
          throw new Error(parseErrorMessage(payload, 'Request failed'));
        }
        return payload;
      });
    });
  }

  function arrayBufferFetch(url) {
    return fetch(url, {
      headers: { 'X-CSRF-Token': getCsrfToken() }
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.text().then(function (txt) {
          var payload = {};
          try {
            payload = txt ? JSON.parse(txt) : {};
          } catch (_) {
            payload = {};
          }
          throw new Error(parseErrorMessage(payload, 'Download failed'));
        });
      }
      return resp.arrayBuffer();
    });
  }

  function triggerBlobDownload(blob, filename) {
    var objectUrl = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename || 'download.bin';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () {
      URL.revokeObjectURL(objectUrl);
    }, 5000);
  }

  // -----------------------------------------------------------------------
  // Download progress toast helpers
  // -----------------------------------------------------------------------
  function showDownloadToast(filename) {
    var toast = document.getElementById('download-toast');
    if (!toast) return;
    toast.classList.remove('hidden');
    var nameEl = document.getElementById('download-toast-filename');
    var pctEl = document.getElementById('download-toast-percent');
    var barEl = document.getElementById('download-toast-bar');
    var statusEl = document.getElementById('download-toast-status');
    var closeBtn = document.getElementById('download-toast-close');
    if (nameEl) nameEl.textContent = filename || 'download';
    if (pctEl) pctEl.textContent = '0%';
    if (barEl) barEl.style.width = '0%';
    if (statusEl) statusEl.textContent = 'Preparing...';
    if (closeBtn) closeBtn.classList.add('hidden');
    // Shift upload panel when both visible
    var uploadPanel = document.getElementById('upload-panel');
    if (uploadPanel && !uploadPanel.classList.contains('hidden')) {
      uploadPanel.style.bottom = (toast.offsetHeight + 24) + 'px';
    }
  }

  function updateDownloadToast(downloaded, total, filename) {
    var pctEl = document.getElementById('download-toast-percent');
    var barEl = document.getElementById('download-toast-bar');
    var statusEl = document.getElementById('download-toast-status');
    var pct = total > 0 ? Math.round((downloaded / total) * 100) : 0;
    if (pctEl) pctEl.textContent = pct + '%';
    if (barEl) barEl.style.width = pct + '%';
    if (statusEl) statusEl.textContent = 'Chunk ' + downloaded + ' of ' + total;
  }

  function finishDownloadToast(success, message) {
    var barEl = document.getElementById('download-toast-bar');
    var statusEl = document.getElementById('download-toast-status');
    var pctEl = document.getElementById('download-toast-percent');
    var closeBtn = document.getElementById('download-toast-close');
    if (success) {
      if (barEl) { barEl.style.width = '100%'; barEl.style.backgroundColor = '#22c55e'; }
      if (statusEl) statusEl.textContent = message || 'Complete';
      if (pctEl) pctEl.textContent = '100%';
    } else {
      if (barEl) barEl.style.backgroundColor = '#ef4444';
      if (statusEl) { statusEl.textContent = message || 'Failed'; statusEl.style.color = '#ef4444'; }
    }
    if (closeBtn) closeBtn.classList.remove('hidden');
    // Auto-hide on success after 3s
    if (success) {
      setTimeout(hideDownloadToast, 3000);
    }
  }

  function hideDownloadToast() {
    var toast = document.getElementById('download-toast');
    if (toast) toast.classList.add('hidden');
    var barEl = document.getElementById('download-toast-bar');
    if (barEl) { barEl.style.backgroundColor = ''; barEl.classList.remove('animate-pulse'); }
    var statusEl = document.getElementById('download-toast-status');
    if (statusEl) statusEl.style.color = '';
    var uploadPanel = document.getElementById('upload-panel');
    if (uploadPanel) uploadPanel.style.bottom = '';
  }

  // Close button for toast
  document.addEventListener('click', function (e) {
    if (e.target.closest('#download-toast-close')) hideDownloadToast();
  });

  function downloadViaChunked(path) {
    var filename = (path || '').split('/').pop() || 'download';
    showDownloadToast(filename);

    return jsonFetch('/files/chunked/download/init?path=' + encodeURIComponent(path))
      .then(function (initPayload) {
        var totalChunks = initPayload.total_chunks || 0;
        var token = initPayload.token;
        filename = initPayload.filename || filename;
        var nameEl = document.getElementById('download-toast-filename');
        if (nameEl) nameEl.textContent = filename;
        updateDownloadToast(0, totalChunks, filename);

        var parts = [];
        var chain = Promise.resolve();

        for (var i = 0; i < totalChunks; i++) {
          (function (idx) {
            chain = chain.then(function () {
              return arrayBufferFetch('/files/chunked/download/chunk?token=' + encodeURIComponent(token) + '&index=' + idx)
                .then(function (ab) {
                  parts.push(new Uint8Array(ab));
                  updateDownloadToast(idx + 1, totalChunks, filename);
                });
            });
          })(i);
        }

        return chain.then(function () {
          var blob = new Blob(parts, { type: initPayload.mime_type || 'application/octet-stream' });
          triggerBlobDownload(blob, filename);
          finishDownloadToast(true, 'Complete — saved');
        });
      })
      .catch(function (err) {
        finishDownloadToast(false, err && err.message ? err.message : 'Download failed');
        throw err;
      });
  }

  function downloadViaSingle(path) {
    var filename = (path || '').split('/').pop() || 'download';
    showDownloadToast(filename);
    var statusEl = document.getElementById('download-toast-status');
    if (statusEl) statusEl.textContent = 'Downloading...';
    var barEl = document.getElementById('download-toast-bar');

    return fetch('/files/download?path=' + encodeURIComponent(path), {
      headers: { 'X-CSRF-Token': getCsrfToken() }
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.text().then(function (txt) {
          var payload = {};
          try { payload = txt ? JSON.parse(txt) : {}; } catch (_) { payload = {}; }
          throw new Error(parseErrorMessage(payload, 'Download failed'));
        });
      }
      // Server redirects on error (Flash<Redirect>). fetch follows redirects
      // silently, returning a 200 HTML page. Detect via Content-Disposition.
      var cd = resp.headers.get('Content-Disposition') || '';
      if (!cd) {
        throw new Error('Download failed — server returned no file');
      }
      var contentLength = parseInt(resp.headers.get('Content-Length') || '0', 10);
      var contentType = resp.headers.get('Content-Type') || 'application/octet-stream';
      // Try to get filename from Content-Disposition header
      var fnMatch = cd.match(/filename\*?=(?:UTF-8''|"?)([^";]+)/i);
      if (fnMatch) filename = decodeURIComponent(fnMatch[1].replace(/"/g, ''));
      var nameEl = document.getElementById('download-toast-filename');
      if (nameEl) nameEl.textContent = filename;

      // If the browser supports ReadableStream, track byte progress
      if (resp.body && typeof resp.body.getReader === 'function' && contentLength > 0) {
        var reader = resp.body.getReader();
        var received = 0;
        var chunks = [];
        return (function readLoop() {
          return reader.read().then(function (result) {
            if (result.done) return chunks;
            chunks.push(result.value);
            received += result.value.length;
            var pct = Math.round((received / contentLength) * 100);
            if (barEl) barEl.style.width = pct + '%';
            var pctEl = document.getElementById('download-toast-percent');
            if (pctEl) pctEl.textContent = pct + '%';
            if (statusEl) statusEl.textContent = formatBytes(received) + ' / ' + formatBytes(contentLength);
            return readLoop();
          });
        })().then(function (chunks) {
          var blob = new Blob(chunks, { type: contentType });
          triggerBlobDownload(blob, filename);
          finishDownloadToast(true, 'Complete — saved');
        });
      }
      // Fallback: no stream support or unknown length — show indeterminate bar
      if (barEl) { barEl.style.width = '100%'; barEl.classList.add('animate-pulse'); }
      var pctEl2 = document.getElementById('download-toast-percent');
      if (pctEl2) pctEl2.textContent = '';
      if (statusEl) statusEl.textContent = 'Downloading...';
      return resp.blob().then(function (blob) {
        if (barEl) barEl.classList.remove('animate-pulse');
        triggerBlobDownload(blob, filename);
        finishDownloadToast(true, 'Complete — saved');
      });
    }).catch(function (err) {
      finishDownloadToast(false, err && err.message ? err.message : 'Download failed');
    });
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(1) + ' GB';
  }

  function shouldUseChunkedDownload(path, fileSize) {
    if (!path) return false;
    if (!Number.isFinite(fileSize) || fileSize <= 0) return false;
    return fileSize > getChunkSizeBytes();
  }

  function downloadFile(path, fileSize) {
    if (shouldUseChunkedDownload(path, fileSize)) {
      return downloadViaChunked(path).catch(function () {
        return downloadViaSingle(path);
      });
    }
    return downloadViaSingle(path);
  }

  // -----------------------------------------------------------------------
  // Dark mode
  // -----------------------------------------------------------------------
  const html = document.documentElement;
  const THEME_KEY = 'irondrive-theme';

  function applyTheme(theme) {
    if (theme === 'dark') {
      html.classList.add('dark');
    } else {
      html.classList.remove('dark');
    }
  }

  // Initialise from localStorage or OS preference
  const stored = localStorage.getItem(THEME_KEY);
  if (stored) {
    applyTheme(stored);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    applyTheme('dark');
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('#dark-mode-toggle');
    if (!btn) return;
    var isDark = html.classList.toggle('dark');
    localStorage.setItem(THEME_KEY, isDark ? 'dark' : 'light');
  });

  // -----------------------------------------------------------------------
  // Sidebar mobile toggle
  // -----------------------------------------------------------------------
  function openSidebar() {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.remove('-translate-x-full');
    if (overlay) overlay.classList.remove('hidden');
  }

  function closeSidebar() {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.add('-translate-x-full');
    if (overlay) overlay.classList.add('hidden');
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('#sidebar-open-btn')) { openSidebar(); return; }
    if (e.target.closest('#sidebar-overlay')) { closeSidebar(); return; }
  });

  // -----------------------------------------------------------------------
  // User menu panel
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('#user-menu-btn');
    var panel = document.getElementById('user-menu-panel');
    if (!panel) return;
    if (btn) {
      panel.classList.toggle('hidden');
      return;
    }
    // Close when clicking outside the panel
    if (!e.target.closest('#user-menu-panel')) {
      panel.classList.add('hidden');
    }
  });

  // -----------------------------------------------------------------------
  // Flash message dismiss
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-dismiss-flash]');
    if (!btn) return;
    var flash = btn.closest('[role="alert"]');
    if (flash) flash.remove();
  });

  // Auto-dismiss flash messages after 5 seconds
  function autoDismissFlashes() {
    var flashes = document.querySelectorAll('[role="alert"][data-auto-dismiss]');
    flashes.forEach(function (f) {
      setTimeout(function () {
        f.style.transition = 'opacity 0.3s';
        f.style.opacity = '0';
        setTimeout(function () { f.remove(); }, 300);
      }, 5000);
    });
  }
  autoDismissFlashes();

  // -----------------------------------------------------------------------
  // Modal helpers
  // -----------------------------------------------------------------------
  function openModal(id) {
    var modal = document.getElementById(id);
    if (!modal) return;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    // Focus first input
    var input = modal.querySelector('input[type="text"], input:not([type="hidden"])');
    if (input) {
      setTimeout(function () { input.focus(); input.select(); }, 50);
    }
  }

  function closeModal(id) {
    var modal = document.getElementById(id);
    if (!modal) return;
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    // Reset form
    var form = modal.querySelector('form');
    if (form) form.reset();
  }

  function closeAllModals() {
    document.querySelectorAll('[role="dialog"]').forEach(function (m) {
      m.classList.add('hidden');
      m.setAttribute('aria-hidden', 'true');
    });
  }

  function normalizeDirPath(path) {
    if (!path) return '';
    return path.trim().replace(/^\/+|\/+$/g, '');
  }

  function getCurrentViewerPath() {
    return normalizeDirPath(new URLSearchParams(window.location.search).get('path') || '');
  }

  function refreshCurrentFileList() {
    if (window.htmx) {
      var path = getCurrentViewerPath();
      var url = '/files/partial' + (path ? '?path=' + encodeURIComponent(path) : '');
      window.htmx.ajax('GET', url, { target: '#file-browser-content', swap: 'innerHTML' });
      return;
    }
    window.location.reload();
  }

  function parentDir(path) {
    var normalized = normalizeDirPath(path);
    var idx = normalized.lastIndexOf('/');
    if (idx < 0) return '';
    return normalized.slice(0, idx);
  }

  // Escape key closes modals
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeAllModals();
  });

  // Click outside modal content closes it
  document.addEventListener('click', function (e) {
    if (e.target.matches('[role="dialog"]')) {
      closeAllModals();
    }
  });

  // Cancel / close buttons inside modals
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-modal-close]');
    if (!btn) return;
    var modal = btn.closest('[role="dialog"]');
    if (modal) closeModal(modal.id);
  });

  // -----------------------------------------------------------------------
  // New Folder modal
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#btn-new-folder')) return;
    openModal('mkdir-modal');
  });

  // -----------------------------------------------------------------------
  // Rename modal
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-rename');
    if (!btn) return;
    var path = btn.getAttribute('data-path');
    var name = btn.getAttribute('data-name');
    var modal = document.getElementById('rename-modal');
    if (!modal) return;
    var pathInput = modal.querySelector('input[name="old_path"]');
    var nameInput = modal.querySelector('input[name="new_name"]');
    if (pathInput) pathInput.value = path;
    if (nameInput) nameInput.value = name;
    openModal('rename-modal');
  });

  // -----------------------------------------------------------------------
  // Move modal (single + bulk)
  // -----------------------------------------------------------------------
  var pendingMovePath = '';
  var pendingBulkMovePaths = null;
  var moveCurrentDir = '';

  function getMoveSourcePaths() {
    var paths = [];
    if (pendingMovePath) {
      paths.push(normalizeDirPath(pendingMovePath));
    }
    if (pendingBulkMovePaths && pendingBulkMovePaths.length > 0) {
      pendingBulkMovePaths.forEach(function (p) {
        paths.push(normalizeDirPath(p));
      });
    }

    // De-duplicate and drop empties.
    var seen = Object.create(null);
    return paths.filter(function (p) {
      if (!p || seen[p]) return false;
      seen[p] = true;
      return true;
    });
  }

  function isInvalidMoveDestination(destPath) {
    var destination = normalizeDirPath(destPath);
    if (!destination) return false;

    var sources = getMoveSourcePaths();
    for (var i = 0; i < sources.length; i++) {
      var source = sources[i];
      if (!source) continue;
      if (destination === source) return true;
      if (destination.startsWith(source + '/')) return true;
    }
    return false;
  }

  function moveFolderListLoading() {
    var list = document.getElementById('move-folder-list');
    if (!list) return;
    list.innerHTML = '<div class="px-3 py-2 text-sm text-gray-500 dark:text-gray-400">Loading folders...</div>';
  }

  function moveFolderListError(msg) {
    var list = document.getElementById('move-folder-list');
    if (!list) return;
    list.innerHTML = '<div class="px-3 py-2 text-sm text-red-500 dark:text-red-400">' + (msg || 'Failed to load folders.') + '</div>';
  }

  function moveFetchFolders(path) {
    var url = '/files/folders?path=' + encodeURIComponent(path || '');
    return fetch(url, {
      headers: { 'X-CSRF-Token': getCsrfToken() }
    }).then(function (resp) {
      return resp.text().then(function (txt) {
        var payload = {};
        try {
          payload = txt ? JSON.parse(txt) : {};
        } catch (_) {
          payload = {};
        }
        if (!resp.ok) {
          throw new Error(parseErrorMessage(payload, 'Failed to load folders'));
        }
        return payload;
      });
    });
  }

  function moveBuildBreadcrumbs(path) {
    var crumbs = [{ name: 'Root', path: '' }];
    if (!path) return crumbs;

    var accumulated = '';
    path.split('/').forEach(function (segment) {
      if (!segment) return;
      accumulated = accumulated ? (accumulated + '/' + segment) : segment;
      crumbs.push({ name: segment, path: accumulated });
    });
    return crumbs;
  }

  function moveRenderBrowser(path, folders) {
    var normalized = normalizeDirPath(path);
    moveCurrentDir = normalized;

    var targetInput = document.getElementById('move-target-dir');
    if (targetInput) targetInput.value = normalized;

    var breadcrumbsEl = document.getElementById('move-breadcrumbs');
    if (breadcrumbsEl) {
      breadcrumbsEl.innerHTML = '';
      var crumbs = moveBuildBreadcrumbs(normalized);

      crumbs.forEach(function (crumb, idx) {
        if (idx > 0) {
          var sep = document.createElement('span');
          sep.className = 'text-gray-400 dark:text-gray-500';
          sep.textContent = '/';
          breadcrumbsEl.appendChild(sep);
        }

        var isLast = idx === crumbs.length - 1;
        if (isLast) {
          var label = document.createElement('span');
          label.className = 'text-gray-700 dark:text-gray-200 truncate';
          label.textContent = crumb.name;
          breadcrumbsEl.appendChild(label);
        } else {
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'text-blue-600 dark:text-blue-400 hover:underline';
          btn.textContent = crumb.name;
          btn.addEventListener('click', function () {
            moveLoadFolder(crumb.path);
          });
          breadcrumbsEl.appendChild(btn);
        }
      });
    }

    var list = document.getElementById('move-folder-list');
    if (!list) return;
    list.innerHTML = '';

    function appendRow(name, clickHandler, isMuted) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'w-full text-left px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700/50 transition-colors flex items-center gap-2';
      if (isMuted) btn.className += ' text-gray-500 dark:text-gray-400';
      btn.innerHTML = '<svg class="w-4 h-4 text-blue-500 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg><span class="truncate"></span>';
      btn.querySelector('span').textContent = name;
      btn.addEventListener('click', clickHandler);
      list.appendChild(btn);
    }

    if (normalized) {
      var parent = normalized.includes('/') ? normalized.slice(0, normalized.lastIndexOf('/')) : '';
      appendRow('..', function () { moveLoadFolder(parent); }, true);
    }

    if (!folders.length) {
      var empty = document.createElement('div');
      empty.className = 'px-3 py-2 text-sm text-gray-500 dark:text-gray-400';
      empty.textContent = 'No subfolders here. Use Move to place items in this folder.';
      list.appendChild(empty);
      return;
    }

    folders.forEach(function (entry) {
      var nextPath = normalizeDirPath(entry.path || '');
      if (isInvalidMoveDestination(nextPath)) return;
      appendRow(entry.name || nextPath, function () { moveLoadFolder(nextPath); }, false);
    });

    if (!list.children.length) {
      var none = document.createElement('div');
      none.className = 'px-3 py-2 text-sm text-gray-500 dark:text-gray-400';
      none.textContent = 'No valid subfolders to move into from here.';
      list.appendChild(none);
    }
  }

  function moveLoadFolder(path) {
    var normalized = normalizeDirPath(path);
    moveFolderListLoading();
    moveFetchFolders(normalized)
      .then(function (payload) {
        var entries = Array.isArray(payload.entries) ? payload.entries : [];
        var folders = entries.filter(function (e) {
          if (!e) return false;
          // /files/folders returns folders-only objects { name, path }.
          // Keep compatibility with older/full listing shapes that include is_dir.
          return typeof e.path === 'string' && (typeof e.is_dir === 'undefined' || e.is_dir === true);
        });
        folders.sort(function (a, b) {
          return (a.name || '').localeCompare((b.name || ''));
        });
        moveRenderBrowser(normalized, folders);
      })
      .catch(function (err) {
        moveFolderListError(err && err.message ? err.message : 'Failed to load folders.');
      });
  }

  function openMoveModal(mode, payload) {
    var modal = document.getElementById('move-modal');
    if (!modal) return;

    var oldPathInput = modal.querySelector('input[name="old_path"]');
    var targetInput = modal.querySelector('input[name="target_dir"]');
    var returnPathInput = modal.querySelector('input[name="return_path"]');
    var subtitle = modal.querySelector('#move-modal-subtitle');
    var submitBtn = modal.querySelector('#move-submit-btn');

    var currentDir = getCurrentViewerPath();
    var startDir = currentDir;
    if (returnPathInput) returnPathInput.value = currentDir;

    if (mode === 'single') {
      pendingMovePath = payload.path;
      pendingBulkMovePaths = null;
      if (oldPathInput) oldPathInput.value = payload.path;
      startDir = parentDir(payload.path || currentDir);
      if (subtitle) subtitle.textContent = 'Select destination folder for "' + payload.name + '".';
      if (submitBtn) submitBtn.textContent = 'Move';
      modal.setAttribute('data-mode', 'single');
    } else {
      pendingMovePath = '';
      pendingBulkMovePaths = payload.paths;
      if (oldPathInput) oldPathInput.value = '';
      if (subtitle) subtitle.textContent = 'Select destination folder for ' + payload.paths.length + ' item' + (payload.paths.length > 1 ? 's' : '') + '.';
      if (submitBtn) submitBtn.textContent = 'Move selected';
      modal.setAttribute('data-mode', 'bulk');

      if (payload.paths && payload.paths.length > 0) {
        startDir = parentDir(payload.paths[0]);
      }
    }

    if (targetInput) targetInput.value = startDir;

    openModal('move-modal');
    moveLoadFolder(startDir);
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-move');
    if (!btn) return;
    openMoveModal('single', {
      path: btn.getAttribute('data-path') || '',
      name: btn.getAttribute('data-name') || 'item'
    });
  });

  // -----------------------------------------------------------------------
  // Multi-file selection
  // -----------------------------------------------------------------------
  var lastCheckedIndex = -1;

  function getSelectedPaths() {
    var checked = document.querySelectorAll('.file-select-cb:checked');
    var paths = [];
    checked.forEach(function (cb) { paths.push(cb.getAttribute('data-path')); });
    return paths;
  }

  function updateSelectionToolbar() {
    var paths = getSelectedPaths();
    var toolbar = document.getElementById('selection-toolbar');
    var countEl = document.getElementById('selection-count');
    if (!toolbar) return;
    if (paths.length === 0) {
      toolbar.classList.add('hidden');
    } else {
      toolbar.classList.remove('hidden');
      if (countEl) countEl.textContent = paths.length + ' selected';
    }
    var selectAll = document.getElementById('select-all-checkbox');
    var allCbs = document.querySelectorAll('.file-select-cb');
    if (selectAll && allCbs.length > 0) {
      selectAll.checked = paths.length === allCbs.length;
      selectAll.indeterminate = paths.length > 0 && paths.length < allCbs.length;
    }
    allCbs.forEach(function (cb) {
      var row = cb.closest('tr');
      if (!row) return;
      if (cb.checked) {
        row.classList.add('bg-blue-50/60', 'dark:bg-blue-900/20');
      } else {
        row.classList.remove('bg-blue-50/60', 'dark:bg-blue-900/20');
      }
    });
  }

  // Select-all checkbox
  document.addEventListener('change', function (e) {
    if (e.target.id !== 'select-all-checkbox') return;
    var checked = e.target.checked;
    document.querySelectorAll('.file-select-cb').forEach(function (cb) {
      cb.checked = checked;
    });
    lastCheckedIndex = -1;
    updateSelectionToolbar();
  });

  // Individual checkbox with Shift+click range selection
  document.addEventListener('click', function (e) {
    var cb = e.target.closest('.file-select-cb');
    if (!cb || cb.id === 'select-all-checkbox') return;
    var allCbs = Array.from(document.querySelectorAll('.file-select-cb'));
    var idx = allCbs.indexOf(cb);
    if (e.shiftKey && lastCheckedIndex >= 0 && lastCheckedIndex !== idx) {
      var start = Math.min(lastCheckedIndex, idx);
      var end = Math.max(lastCheckedIndex, idx);
      var state = cb.checked;
      for (var i = start; i <= end; i++) {
        allCbs[i].checked = state;
      }
    }
    lastCheckedIndex = idx;
    updateSelectionToolbar();
  });

  // Clear selection button
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#selection-clear-btn')) return;
    document.querySelectorAll('.file-select-cb').forEach(function (cb) { cb.checked = false; });
    var selectAll = document.getElementById('select-all-checkbox');
    if (selectAll) { selectAll.checked = false; selectAll.indeterminate = false; }
    lastCheckedIndex = -1;
    updateSelectionToolbar();
  });

  // Bulk download
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#bulk-download-btn')) return;
    var paths = getSelectedPaths();
    var chain = Promise.resolve();
    paths.forEach(function (p) {
      var row = document.querySelector('tr[data-path="' + CSS.escape(p) + '"]');
      var isDir = row && row.getAttribute('data-is-dir') === 'true';
      if (!isDir) {
        var size = parseInt(row.getAttribute('data-size') || '0', 10);
        chain = chain.then(function () {
          return downloadFile(p, size);
        });
      }
    });
  });

  // Bulk move
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#bulk-move-btn')) return;
    var paths = getSelectedPaths();
    if (paths.length === 0) return;
    openMoveModal('bulk', { paths: paths });
  });

  // Intercept ALL file download links so we can show the progress toast.
  document.addEventListener('click', function (e) {
    var link = e.target.closest('a[href^="/files/download?path="]');
    if (!link) return;

    var row = link.closest('tr[data-path]');
    if (!row) return;
    if (row.getAttribute('data-is-dir') === 'true') return;

    e.preventDefault();

    var path = row.getAttribute('data-path') || '';
    var size = parseInt(row.getAttribute('data-size') || '0', 10);
    downloadFile(path, size);
  });

  // Bulk delete — open confirm modal
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#bulk-delete-btn')) return;
    var paths = getSelectedPaths();
    if (paths.length === 0) return;
    var modal = document.getElementById('confirm-modal');
    if (!modal) return;
    var msg = modal.querySelector('#confirm-message');
    if (msg) msg.textContent = 'Are you sure you want to delete ' + paths.length + ' item' + (paths.length > 1 ? 's' : '') + '? This cannot be undone.';
    pendingBulkDeletePaths = paths;
    openModal('confirm-modal');
  });

  var pendingBulkDeletePaths = null;

  // -----------------------------------------------------------------------
  // Delete confirmation modal (single + bulk)
  // -----------------------------------------------------------------------
  var pendingDeletePath = '';
  var pendingDeleteName = '';

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-delete');
    if (!btn) return;
    pendingDeletePath = btn.getAttribute('data-path');
    pendingDeleteName = btn.getAttribute('data-name');
    pendingBulkDeletePaths = null;
    var modal = document.getElementById('confirm-modal');
    if (!modal) return;
    var msg = modal.querySelector('#confirm-message');
    if (msg) msg.textContent = 'Are you sure you want to delete "' + pendingDeleteName + '"? This cannot be undone.';
    openModal('confirm-modal');
  });

  document.addEventListener('click', function (e) {
    if (!e.target.closest('#confirm-action')) return;

    // Bulk delete path
    if (pendingBulkDeletePaths && pendingBulkDeletePaths.length > 0) {
      var paths = pendingBulkDeletePaths;
      pendingBulkDeletePaths = null;
      closeAllModals();
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/files/bulk-delete', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());
      xhr.addEventListener('load', function () { window.location.reload(); });
      xhr.addEventListener('error', function () { window.location.reload(); });
      xhr.send(JSON.stringify({ paths: paths }));
      return;
    }

    // Single delete path
    if (!pendingDeletePath) return;
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/files/delete';
    var csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrf_token';
    csrfInput.value = getCsrfToken();
    form.appendChild(csrfInput);
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'path';
    input.value = pendingDeletePath;
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
    pendingDeletePath = '';
    pendingDeleteName = '';
  });

  // Move submit (single form submit or bulk XHR)
  document.addEventListener('submit', function (e) {
    if (e.target.id !== 'move-form') return;

    var form = e.target;
    var modal = document.getElementById('move-modal');
    var mode = modal ? modal.getAttribute('data-mode') : 'single';
    var targetInput = form.querySelector('input[name="target_dir"]');
    var targetDir = normalizeDirPath(targetInput ? targetInput.value : moveCurrentDir);

    if (mode === 'bulk') {
      e.preventDefault();
      var paths = pendingBulkMovePaths || [];
      if (paths.length === 0) {
        closeAllModals();
        return;
      }

      closeAllModals();
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/files/bulk-move', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());
      xhr.addEventListener('load', function () { refreshCurrentFileList(); });
      xhr.addEventListener('error', function () { refreshCurrentFileList(); });
      xhr.send(JSON.stringify({ paths: paths, target_dir: targetDir }));

      pendingBulkMovePaths = null;
      pendingMovePath = '';
      return;
    }

    var oldPathInput = form.querySelector('input[name="old_path"]');
    if (oldPathInput && !oldPathInput.value && pendingMovePath) {
      oldPathInput.value = pendingMovePath;
    }

    var returnPathInput = form.querySelector('input[name="return_path"]');
    if (returnPathInput) {
      returnPathInput.value = getCurrentViewerPath();
    }
  });

  // -----------------------------------------------------------------------
  // Drag & drop move in file viewer
  // -----------------------------------------------------------------------
  var dragMoveState = null;
  var dragOverFolderRow = null;

  function clearDragOverFolder() {
    if (!dragOverFolderRow) return;
    dragOverFolderRow.classList.remove('bg-blue-100/60', 'dark:bg-blue-900/30');
    dragOverFolderRow = null;
  }

  function setDragOverFolder(row) {
    if (dragOverFolderRow === row) return;
    clearDragOverFolder();
    dragOverFolderRow = row;
    dragOverFolderRow.classList.add('bg-blue-100/60', 'dark:bg-blue-900/30');
  }

  function executeBulkMove(paths, targetDir) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/files/bulk-move', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());

      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          reject(new Error('Move failed'));
        }
      });
      xhr.addEventListener('error', function () { reject(new Error('Network error')); });
      xhr.send(JSON.stringify({ paths: paths, target_dir: normalizeDirPath(targetDir) }));
    });
  }

  function canDropIntoTarget(paths, targetDir) {
    var normalizedTarget = normalizeDirPath(targetDir);
    for (var i = 0; i < paths.length; i++) {
      var source = normalizeDirPath(paths[i]);
      if (!source) return false;
      if (normalizedTarget === source) return false;
      if (normalizedTarget.startsWith(source + '/')) return false;
    }
    return true;
  }

  document.addEventListener('dragstart', function (e) {
    var row = e.target.closest('tr[data-path]');
    if (!row) return;

    if (e.target.closest('a,button,input,label')) {
      e.preventDefault();
      return;
    }

    var rowPath = row.getAttribute('data-path') || '';
    var selectedPaths = getSelectedPaths();
    var paths = (selectedPaths.length > 1 && selectedPaths.indexOf(rowPath) >= 0)
      ? selectedPaths.slice()
      : [rowPath];

    dragMoveState = { paths: paths };
    row.classList.add('opacity-60');

    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', rowPath);
      e.dataTransfer.setData('text/x-irondrive-move', JSON.stringify(paths));
    }
  });

  document.addEventListener('dragend', function () {
    clearDragOverFolder();
    document.querySelectorAll('tr[data-path].opacity-60').forEach(function (row) {
      row.classList.remove('opacity-60');
    });
    dragMoveState = null;
  });

  document.addEventListener('dragover', function (e) {
    if (!dragMoveState || !dragMoveState.paths || dragMoveState.paths.length === 0) return;
    var folderRow = e.target.closest('tr[data-path][data-is-dir="true"]');
    if (!folderRow) return;

    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    setDragOverFolder(folderRow);
  });

  document.addEventListener('dragleave', function (e) {
    if (!dragOverFolderRow) return;
    if (e.target === dragOverFolderRow || dragOverFolderRow.contains(e.target)) {
      var related = e.relatedTarget;
      if (!related || !dragOverFolderRow.contains(related)) {
        clearDragOverFolder();
      }
    }
  });

  document.addEventListener('drop', function (e) {
    if (!dragMoveState || !dragMoveState.paths || dragMoveState.paths.length === 0) return;
    var folderRow = e.target.closest('tr[data-path][data-is-dir="true"]');
    if (!folderRow) return;

    e.preventDefault();
    e.stopPropagation();

    var targetDir = folderRow.getAttribute('data-path') || '';
    var paths = dragMoveState.paths.slice();

    clearDragOverFolder();

    if (!canDropIntoTarget(paths, targetDir)) {
      dragMoveState = null;
      document.querySelectorAll('tr[data-path].opacity-60').forEach(function (row) {
        row.classList.remove('opacity-60');
      });
      return;
    }

    executeBulkMove(paths, targetDir)
      .then(function () { refreshCurrentFileList(); })
      .catch(function () { refreshCurrentFileList(); })
      .finally(function () {
        dragMoveState = null;
        document.querySelectorAll('tr[data-path].opacity-60').forEach(function (row) {
          row.classList.remove('opacity-60');
        });
      });
  });

  // -----------------------------------------------------------------------
  // Prevent double form submission
  // -----------------------------------------------------------------------
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (form.dataset.submitted === 'true') {
      e.preventDefault();
      return;
    }
    form.dataset.submitted = 'true';
    var btn = form.querySelector('button[type="submit"]');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('opacity-50', 'cursor-not-allowed');
    }
    // Reset after 5 seconds in case of slow redirect
    setTimeout(function () {
      form.dataset.submitted = '';
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    }, 5000);
  });

  // -----------------------------------------------------------------------
  // Client-side column sorting
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var th = e.target.closest('[data-sort]');
    if (!th) return;
    var key = th.getAttribute('data-sort');
    var tbody = document.getElementById('file-tbody');
    if (!tbody) return;
    var rows = Array.from(tbody.querySelectorAll('tr'));
    var ascending = th.getAttribute('data-sort-dir') !== 'asc';
    th.setAttribute('data-sort-dir', ascending ? 'asc' : 'desc');

    rows.sort(function (a, b) {
      // Directories always come first
      var aDir = a.getAttribute('data-is-dir') === 'true';
      var bDir = b.getAttribute('data-is-dir') === 'true';
      if (aDir !== bDir) return aDir ? -1 : 1;

      var aVal, bVal;
      if (key === 'name') {
        aVal = (a.getAttribute('data-name') || '').toLowerCase();
        bVal = (b.getAttribute('data-name') || '').toLowerCase();
        return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      } else if (key === 'size') {
        aVal = parseInt(a.getAttribute('data-size') || '0', 10);
        bVal = parseInt(b.getAttribute('data-size') || '0', 10);
      } else if (key === 'modified') {
        aVal = a.getAttribute('data-modified') || '';
        bVal = b.getAttribute('data-modified') || '';
        return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }
      return ascending ? aVal - bVal : bVal - aVal;
    });

    rows.forEach(function (row) { tbody.appendChild(row); });
  });

  // -----------------------------------------------------------------------
  // Re-initialise after HTMX swap
  // -----------------------------------------------------------------------
  document.addEventListener('htmx:afterSwap', function () {
    autoDismissFlashes();
    initFileKeyboardNav();
    lastCheckedIndex = -1;
    updateSelectionToolbar();
    // Keep mkdir-form path in sync after HTMX navigation
    var mkdirPath = document.querySelector('#mkdir-form input[name="path"]');
    if (mkdirPath) {
      mkdirPath.value = new URLSearchParams(window.location.search).get('path') || '';
    }
  });

  // -----------------------------------------------------------------------
  // Keyboard navigation for file list
  // -----------------------------------------------------------------------
  function initFileKeyboardNav() {
    var rows = document.querySelectorAll('#file-tbody tr');
    rows.forEach(function (row) {
      if (!row.getAttribute('tabindex')) {
        row.setAttribute('tabindex', '0');
        row.setAttribute('role', 'row');
      }
      if (row.hasAttribute('data-path')) {
        row.setAttribute('draggable', 'true');
      }
    });
  }
  initFileKeyboardNav();

  document.addEventListener('keydown', function (e) {
    var row = e.target.closest('#file-tbody tr');
    if (!row) return;

    var rows = Array.from(document.querySelectorAll('#file-tbody tr'));
    var idx = rows.indexOf(row);
    if (idx === -1) return;

    if (e.key === 'ArrowDown' && idx < rows.length - 1) {
      e.preventDefault();
      rows[idx + 1].focus();
    } else if (e.key === 'ArrowUp' && idx > 0) {
      e.preventDefault();
      rows[idx - 1].focus();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      var link = row.querySelector('td:first-child a');
      if (link) link.click();
    }
  });

  // -----------------------------------------------------------------------
  // hx-indicator loading states
  // -----------------------------------------------------------------------
  document.addEventListener('htmx:beforeRequest', function (e) {
    var indicator = document.getElementById('htmx-loading');
    if (indicator) indicator.classList.remove('hidden');
  });

  document.addEventListener('htmx:afterRequest', function (e) {
    var indicator = document.getElementById('htmx-loading');
    if (indicator) indicator.classList.add('hidden');
  });

})();
