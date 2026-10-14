// A browser visit can nudge the scheduler with POST. A plain GET does not.
(function () {
  if (!window.fetch) {
    return;
  }
  fetch('api/work.php', { method: 'POST', credentials: 'omit' }).catch(function () {});
})();
