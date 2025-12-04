(function () {
  const rawBase =
    (window.APP_CONFIG && window.APP_CONFIG.apiBase) ||
    (typeof API_BASE_OVERRIDE !== 'undefined' ? API_BASE_OVERRIDE : '');

  const defaultBase =
    window.location.hostname === 'localhost' ? 'http://localhost:5000' : window.location.origin;
  const base = (rawBase || defaultBase || '').replace(/\/$/, '');

  window.API = {
    base,
    url(path) {
      if (!path.startsWith('/')) {
        return `${base}/${path}`;
      }
      return `${base}${path}`;
    }
  };
})();
