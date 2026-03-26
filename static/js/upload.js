// IronDrive – upload.js (vanilla JS, XHR upload with progress)
(function () {
  'use strict';

  // State
  var uploads = [];
  var nextId = 1;

  function getCsrfToken() {
    var match = document.cookie.match('(?:^|; )csrf_token=([^;]*)');
    return match ? decodeURIComponent(match[1]) : '';
  }

  // DOM references (lazy, resolved after each HTMX swap)
  function getPanel() { return document.getElementById('upload-panel'); }
  function getPanelList() { return document.getElementById('upload-panel-list'); }
  function getTbody() { return document.getElementById('file-tbody'); }
  function getFileInput() { return document.getElementById('file-upload-input'); }
  function getDropZone() { return document.getElementById('drop-zone'); }

  // Current directory path from the URL (HTMX keeps it updated via hx-push-url)
  function getCurrentPath() {
    var params = new URLSearchParams(window.location.search);
    return params.get('path') || '';
  }

  // -----------------------------------------------------------------------
  // Upload Panel UI
  // -----------------------------------------------------------------------
  function showPanel() {
    var panel = getPanel();
    if (panel) panel.classList.remove('hidden');
  }

  function hidePanel() {
    var panel = getPanel();
    if (panel) panel.classList.add('hidden');
  }

  function toggleMinimise() {
    var list = getPanelList();
    if (!list) return;
    list.classList.toggle('hidden');
  }

  function createUploadRow(id, filename) {
    var div = document.createElement('div');
    div.id = 'upload-item-' + id;
    div.className = 'px-3 py-2 border-b border-gray-100 dark:border-gray-700 last:border-0';
    div.innerHTML =
      '<div class="flex items-center justify-between mb-1">' +
        '<span class="text-sm text-gray-700 dark:text-gray-300 truncate max-w-[180px]" title="' + escapeHtml(filename) + '">' + escapeHtml(filename) + '</span>' +
        '<span class="upload-status text-xs text-gray-400">0%</span>' +
      '</div>' +
      '<div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">' +
        '<div class="upload-bar h-full bg-blue-600 rounded-full transition-all duration-150" style="width: 0%"></div>' +
      '</div>';
    return div;
  }

  function updateUploadRow(id, pct) {
    var row = document.getElementById('upload-item-' + id);
    if (!row) return;
    var bar = row.querySelector('.upload-bar');
    var status = row.querySelector('.upload-status');
    if (bar) bar.style.width = pct + '%';
    if (status) status.textContent = pct + '%';
  }

  function markUploadProcessing(id) {
    var row = document.getElementById('upload-item-' + id);
    if (!row) return;
    var bar = row.querySelector('.upload-bar');
    var status = row.querySelector('.upload-status');
    if (bar) { bar.style.width = '100%'; bar.classList.add('animate-pulse'); }
    if (status) status.textContent = 'Encrypting…';
  }

  function markUploadComplete(id) {
    var row = document.getElementById('upload-item-' + id);
    if (!row) return;
    var bar = row.querySelector('.upload-bar');
    var status = row.querySelector('.upload-status');
    if (bar) { bar.style.width = '100%'; bar.classList.remove('animate-pulse'); bar.classList.replace('bg-blue-600', 'bg-green-500'); }
    if (status) { status.textContent = 'Done'; status.classList.replace('text-gray-400', 'text-green-600'); }
  }

  function markUploadFailed(id, msg) {
    var row = document.getElementById('upload-item-' + id);
    if (!row) return;
    var bar = row.querySelector('.upload-bar');
    var status = row.querySelector('.upload-status');
    if (bar) { bar.classList.remove('animate-pulse'); bar.classList.replace('bg-blue-600', 'bg-red-500'); }
    if (status) { status.textContent = msg || 'Failed'; status.classList.replace('text-gray-400', 'text-red-600'); }
  }

  // -----------------------------------------------------------------------
  // Placeholder (ghost) rows in file table
  // -----------------------------------------------------------------------
  function addGhostRow(id, filename) {
    var tbody = getTbody();
    if (!tbody) return;
    var tr = document.createElement('tr');
    tr.id = 'ghost-' + id;
    tr.className = 'opacity-50 animate-pulse';
    tr.innerHTML =
      '<td class="py-2 pl-2 pr-4">' +
        '<div class="flex items-center gap-2.5">' +
          '<svg class="w-5 h-5 flex-shrink-0 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>' +
          '<span class="text-gray-400 dark:text-gray-500 truncate">' + escapeHtml(filename) + '</span>' +
        '</div>' +
      '</td>' +
      '<td class="py-2 px-4 hidden sm:table-cell"><span class="text-gray-300 dark:text-gray-600">Uploading…</span></td>' +
      '<td class="py-2 px-4 hidden md:table-cell"></td>' +
      '<td class="py-2 px-4"></td>';
    tbody.appendChild(tr);
  }

  function removeGhostRow(id) {
    var ghost = document.getElementById('ghost-' + id);
    if (ghost) ghost.remove();
  }

  // -----------------------------------------------------------------------
  // Core upload function
  // -----------------------------------------------------------------------
  function uploadFile(file) {
    var id = nextId++;
    var currentPath = getCurrentPath();
    var fullPath = currentPath ? (currentPath + '/' + file.name) : file.name;

    // Show UI
    showPanel();
    var panelList = getPanelList();
    if (panelList) {
      panelList.appendChild(createUploadRow(id, file.name));
    }
    addGhostRow(id, file.name);

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/files/upload?path=' + encodeURIComponent(fullPath), true);
    xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());

    xhr.upload.addEventListener('progress', function (e) {
      if (e.lengthComputable) {
        var pct = Math.round((e.loaded / e.total) * 100);
        updateUploadRow(id, pct);
      }
    });

    xhr.addEventListener('load', function () {
      removeGhostRow(id);
      if (xhr.status >= 200 && xhr.status < 300) {
        markUploadComplete(id);
        refreshFileList();
      } else {
        var msg = 'Failed';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp.error) msg = resp.error;
        } catch (_) { /* ignore parse errors */ }
        markUploadFailed(id, msg);
      }
    });

    xhr.addEventListener('error', function () {
      removeGhostRow(id);
      markUploadFailed(id, 'Network error');
    });

    xhr.addEventListener('loadend', function () {
      // Remove from active uploads
      uploads = uploads.filter(function (u) { return u.id !== id; });
    });

    // Mark as processing once upload bytes are sent
    xhr.upload.addEventListener('load', function () {
      markUploadProcessing(id);
    });

    uploads.push({ id: id, xhr: xhr, name: file.name });
    xhr.send(file);
  }

  // Refresh the file list via HTMX after upload
  function refreshFileList() {
    var container = document.getElementById('file-browser-content');
    if (container && window.htmx) {
      var path = getCurrentPath();
      var url = '/files/partial' + (path ? '?path=' + encodeURIComponent(path) : '');
      window.htmx.ajax('GET', url, { target: '#file-browser-content', swap: 'innerHTML' });
    }
  }

  // -----------------------------------------------------------------------
  // File input change handler
  // -----------------------------------------------------------------------
  document.addEventListener('change', function (e) {
    if (e.target.id !== 'file-upload-input') return;
    var files = e.target.files;
    if (!files || files.length === 0) return;
    for (var i = 0; i < files.length; i++) {
      uploadFile(files[i]);
    }
    e.target.value = '';
  });

  // -----------------------------------------------------------------------
  // Drag and drop
  // -----------------------------------------------------------------------
  var dragCounter = 0;

  document.addEventListener('dragenter', function (e) {
    e.preventDefault();
    dragCounter++;
    var dz = getDropZone();
    if (dz && dragCounter === 1) dz.classList.remove('hidden');
  });

  document.addEventListener('dragleave', function (e) {
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      var dz = getDropZone();
      if (dz) dz.classList.add('hidden');
    }
  });

  document.addEventListener('dragover', function (e) {
    e.preventDefault();
  });

  document.addEventListener('drop', function (e) {
    e.preventDefault();
    dragCounter = 0;
    var dz = getDropZone();
    if (dz) dz.classList.add('hidden');

    var files = e.dataTransfer && e.dataTransfer.files;
    if (!files || files.length === 0) return;

    // Only upload if we're on the files page
    if (!document.getElementById('file-browser-content')) return;

    for (var i = 0; i < files.length; i++) {
      uploadFile(files[i]);
    }
  });

  // -----------------------------------------------------------------------
  // Panel controls
  // -----------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    if (e.target.closest('#upload-panel-minimize')) {
      toggleMinimise();
    }
    if (e.target.closest('#upload-panel-clear')) {
      var panelList = getPanelList();
      if (panelList) panelList.innerHTML = '';
      // Hide panel if no active uploads
      if (uploads.length === 0) hidePanel();
    }
  });

  // -----------------------------------------------------------------------
  // Utility
  // -----------------------------------------------------------------------
  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

})();
