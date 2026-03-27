// IronDrive – upload.js (vanilla JS, XHR upload with progress)
(function () {
  'use strict';

  // State
  var uploads = [];
  var nextId = 1;
  var GHOST_MIN_VISIBLE_MS = 450;

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

  function getChunkSizeBytes() {
    var root = document.getElementById('file-browser-content');
    if (!root) return 8 * 1024 * 1024;
    var raw = root.getAttribute('data-chunk-size-bytes');
    var parsed = parseInt(raw || '', 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 8 * 1024 * 1024;
    return parsed;
  }

  function getMaxParallelChunks() {
    var root = document.getElementById('file-browser-content');
    if (!root) return 4;
    var raw = root.getAttribute('data-max-parallel-chunks');
    var parsed = parseInt(raw || '', 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 4;
    return Math.min(parsed, 16);
  }

  function parseErrorMessage(payload, fallback) {
    if (!payload) return fallback;
    if (typeof payload === 'string') return payload;
    if (payload.error && typeof payload.error === 'string') return payload.error;
    if (payload.error && payload.error.description) return payload.error.description;
    if (payload.message && typeof payload.message === 'string') return payload.message;
    return fallback;
  }

  function jsonRequest(method, url, body) {
    return fetch(url, {
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify(body)
    }).then(function (resp) {
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

  function createUploadRow(id, filename, mode) {
    var modeBadge = mode === 'chunked'
      ? '<span class="ml-1 text-xs text-gray-400 dark:text-gray-500">· multipart</span>'
      : '';

    var div = document.createElement('div');
    div.id = 'upload-item-' + id;
    div.className = 'px-3 py-2 border-b border-gray-100 dark:border-gray-700 last:border-0';
    div.innerHTML =
      '<div class="flex items-center justify-between mb-1">' +
        '<span class="flex min-w-0 items-center text-sm text-gray-700 dark:text-gray-300 truncate max-w-[300px]" title="' + escapeHtml(filename) + '"><span class="truncate">' + escapeHtml(filename) + '</span>' + modeBadge + '</span>' +
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
  function ensureGhostTbody() {
    var tbody = getTbody();
    if (tbody) return tbody;

    var root = document.getElementById('file-browser-content');
    if (!root) return null;

    var emptyState = root.querySelector('.card.text-center');
    if (emptyState) emptyState.remove();

    var shell = document.createElement('div');
    shell.className = 'card overflow-hidden';
    shell.innerHTML =
      '<div class="overflow-x-auto">' +
        '<table class="w-full text-sm" id="file-table">' +
          '<thead>' +
            '<tr class="border-b border-gray-200 dark:border-gray-700 text-left text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50/50 dark:bg-gray-800/50">' +
              '<th class="py-3 pl-3 pr-1 w-8"><input type="checkbox" id="select-all-checkbox" class="file-checkbox" aria-label="Select all files"></th>' +
              '<th class="py-3 pl-2 pr-4 font-medium cursor-pointer select-none" data-sort="name">Name</th>' +
              '<th class="py-3 px-4 font-medium cursor-pointer select-none hidden sm:table-cell" data-sort="size">Size</th>' +
              '<th class="py-3 px-4 font-medium cursor-pointer select-none hidden md:table-cell" data-sort="modified">Modified</th>' +
              '<th class="py-3 px-4 font-medium text-right">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody class="divide-y divide-gray-100 dark:divide-gray-800" id="file-tbody"></tbody>' +
        '</table>' +
      '</div>';

    root.appendChild(shell);
    return getTbody();
  }

  function addGhostRow(id, filename) {
    var tbody = ensureGhostTbody();
    if (!tbody) return;
    var tr = document.createElement('tr');
    tr.id = 'ghost-' + id;
    tr.className = 'opacity-60 animate-pulse';
    tr.setAttribute('data-added-at', String(Date.now()));
    tr.innerHTML =
      '<td class="py-2.5 pl-3 pr-1 w-8">' +
        '<span class="block w-4 h-4 rounded border-2 border-gray-200 dark:border-gray-700"></span>' +
      '</td>' +
      '<td class="py-2.5 pl-2 pr-4">' +
        '<div class="flex items-center gap-2.5">' +
          '<svg class="w-5 h-5 flex-shrink-0 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>' +
          '<span class="text-gray-400 dark:text-gray-500 truncate">' + escapeHtml(filename) + '</span>' +
        '</div>' +
      '</td>' +
      '<td class="py-2.5 px-4 text-gray-300 dark:text-gray-600 whitespace-nowrap hidden sm:table-cell">Uploading…</td>' +
      '<td class="py-2.5 px-4 hidden md:table-cell"></td>' +
      '<td class="py-2.5 px-4"></td>';
    tbody.appendChild(tr);
  }

  function removeGhostRow(id, done) {
    var ghost = document.getElementById('ghost-' + id);
    if (!ghost) {
      if (typeof done === 'function') done();
      return;
    }

    var addedAt = parseInt(ghost.getAttribute('data-added-at') || '0', 10);
    var elapsed = Date.now() - addedAt;
    var wait = Math.max(0, GHOST_MIN_VISIBLE_MS - elapsed);

    setTimeout(function () {
      var current = document.getElementById('ghost-' + id);
      if (current) current.remove();
      if (typeof done === 'function') done();
    }, wait);
  }

  // -----------------------------------------------------------------------
  // Core upload functions
  // -----------------------------------------------------------------------
  function uploadFileSingle(id, file, fullPath) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/files/upload?path=' + encodeURIComponent(fullPath), true);
      xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());

      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) {
          var pct = Math.round((e.loaded / e.total) * 100);
          updateUploadRow(id, pct);
        }
      });

      xhr.upload.addEventListener('load', function () {
        markUploadProcessing(id);
      });

      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          var msg = 'Upload failed';
          try {
            var payload = JSON.parse(xhr.responseText);
            msg = parseErrorMessage(payload, msg);
          } catch (_) { /* ignore */ }
          reject(new Error(msg));
        }
      });

      xhr.addEventListener('error', function () {
        reject(new Error('Network error'));
      });

      uploads.push({ id: id, xhr: xhr, name: file.name });
      xhr.send(file);
    });
  }

  function uploadChunkXhr(uploadId, chunkIndex, chunkBlob, onProgress) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open('PUT', '/files/chunked/upload/' + encodeURIComponent(uploadId) + '/' + chunkIndex, true);
      xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());

      xhr.upload.addEventListener('progress', function (e) {
        if (!e.lengthComputable) return;
        onProgress(e.loaded);
      });

      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          var msg = 'Chunk upload failed';
          try {
            var payload = JSON.parse(xhr.responseText);
            msg = parseErrorMessage(payload, msg);
          } catch (_) { /* ignore */ }
          reject(new Error(msg));
        }
      });

      xhr.addEventListener('error', function () {
        reject(new Error('Network error'));
      });

      xhr.send(chunkBlob);
    });
  }

  function uploadFileChunked(id, file, fullPath) {
    var chunkSize = getChunkSizeBytes();
    var totalChunks = Math.ceil(file.size / chunkSize);
    var maxParallel = Math.min(getMaxParallelChunks(), totalChunks);
    var uploadId = '';

    return jsonRequest('POST', '/files/chunked/init', {
      path: fullPath,
      total_chunks: totalChunks,
      total_bytes: file.size
    }).then(function (initPayload) {
      uploadId = initPayload.upload_id;

      var committedBytes = 0;
      var inflightBytes = Object.create(null);
      var nextChunkIndex = 0;

      function reportProgress() {
        var pending = 0;
        Object.keys(inflightBytes).forEach(function (key) {
          pending += inflightBytes[key] || 0;
        });
        var uploaded = Math.min(file.size, committedBytes + pending);
        var pct = Math.min(99, Math.round((uploaded / file.size) * 100));
        updateUploadRow(id, pct);
      }

      function uploadOneChunk(chunkIndex) {
        var start = chunkIndex * chunkSize;
        var end = Math.min(start + chunkSize, file.size);
        var chunk = file.slice(start, end);
        var key = String(chunkIndex);
        inflightBytes[key] = 0;

        return uploadChunkXhr(uploadId, chunkIndex, chunk, function (loaded) {
          inflightBytes[key] = loaded;
          reportProgress();
        }).then(function () {
          committedBytes += chunk.size;
          delete inflightBytes[key];
          reportProgress();
        }).catch(function (err) {
          delete inflightBytes[key];
          throw err;
        });
      }

      function worker() {
        if (nextChunkIndex >= totalChunks) {
          return Promise.resolve();
        }
        var chunkIndex = nextChunkIndex;
        nextChunkIndex += 1;
        return uploadOneChunk(chunkIndex).then(worker);
      }

      var workers = [];
      for (var i = 0; i < maxParallel; i++) {
        workers.push(worker());
      }
      return Promise.all(workers);
    }).then(function () {
      markUploadProcessing(id);
      return jsonRequest('POST', '/files/chunked/complete', {
        upload_id: uploadId,
        verify: false
      });
    }).catch(function (err) {
      if (!uploadId) {
        throw err;
      }

      return fetch('/files/chunked/cancel?upload_id=' + encodeURIComponent(uploadId), {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': getCsrfToken() }
      }).catch(function () {
        return null;
      }).then(function () {
        throw err;
      });
    });
  }

  function uploadFile(file) {
    var id = nextId++;
    var currentPath = getCurrentPath();
    var fullPath = currentPath ? (currentPath + '/' + file.name) : file.name;
    var chunkSize = getChunkSizeBytes();
    var shouldUseChunked = file.size > chunkSize;

    // Show UI
    showPanel();
    var panelList = getPanelList();
    if (panelList) {
      panelList.appendChild(createUploadRow(id, file.name, shouldUseChunked ? 'chunked' : 'single'));
    }
    addGhostRow(id, file.name);

    var promise = shouldUseChunked
      ? uploadFileChunked(id, file, fullPath)
      : uploadFileSingle(id, file, fullPath);

    promise.then(function () {
      removeGhostRow(id, function () {
        markUploadComplete(id);
        refreshFileList();
      });
    }).catch(function (err) {
      removeGhostRow(id, function () {
        markUploadFailed(id, err && err.message ? err.message : 'Upload failed');
      });
    }).finally(function () {
      uploads = uploads.filter(function (u) { return u.id !== id; });
    });
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

  function isFileDragEvent(e) {
    var dt = e.dataTransfer;
    if (!dt || !dt.types) return false;
    for (var i = 0; i < dt.types.length; i++) {
      if (dt.types[i] === 'Files') return true;
    }
    return false;
  }

  document.addEventListener('dragenter', function (e) {
    if (!isFileDragEvent(e)) return;
    e.preventDefault();
    dragCounter++;
    var dz = getDropZone();
    if (dz && dragCounter === 1) dz.classList.remove('hidden');
  });

  document.addEventListener('dragleave', function (e) {
    if (!isFileDragEvent(e)) return;
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      var dz = getDropZone();
      if (dz) dz.classList.add('hidden');
    }
  });

  document.addEventListener('dragover', function (e) {
    if (!isFileDragEvent(e)) return;
    e.preventDefault();
  });

  document.addEventListener('drop', function (e) {
    if (!isFileDragEvent(e)) return;
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
    if (e.target.closest('#upload-panel-toggle')) {
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
