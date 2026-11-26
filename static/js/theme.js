// IronDrive – theme.js
// Loaded synchronously in <head> (not deferred) so the theme and sidebar
// state are applied before first paint — no light-mode flash, no layout jump.
(function () {
  var root = document.documentElement;
  var theme = null;
  try { theme = localStorage.getItem('irondrive-theme'); } catch (_) { /* storage blocked */ }
  if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    root.classList.add('dark');
  }
  try {
    if (localStorage.getItem('irondrive-sidebar') === 'collapsed') root.classList.add('sidebar-collapsed');
  } catch (_) { /* ignore */ }
})();
