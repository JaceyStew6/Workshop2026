/* Utilitaires partagés. Aucune donnée n'est jamais insérée via innerHTML : tout passe par textContent (anti-XSS). */
(function () {
  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, '');
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
    return e;
  };

  async function api(method, url, body, token) {
    try {
      const r = await fetch(url, {
        method,
        headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      let data = null;
      try { data = await r.json(); } catch { /* corps vide */ }
      return { ok: r.ok, status: r.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    }
  }

  const LED_LABEL = {
    off: 'éteint', green_blink: 'vert clignotant', green_solid: 'vert fixe', red_blink: 'rouge clignotant', red_solid: 'rouge fixe',
  };

  /* Voyant virtuel : même vocabulaire de motifs que le firmware (off, green_blink, green_solid, red_blink, red_solid). */
  function ledWidget() {
    const el = h('span', { class: 'led off', role: 'img', 'aria-label': 'Voyant : éteint' });
    const txt = h('span', { class: 'muted' }, 'éteint');
    const box = h('span', { class: 'row', style: 'gap:6px' }, el, txt);
    return {
      el: box,
      set(pattern) {
        const p = LED_LABEL[pattern] ? pattern : 'off';
        el.className = 'led ' + p;
        el.setAttribute('aria-label', 'Voyant : ' + LED_LABEL[p]);
        txt.textContent = LED_LABEL[p];
      },
    };
  }

  function detail(res, fallback) {
    return (res.data && (res.data.detail && typeof res.data.detail === 'string' ? res.data.detail : res.data.error)) || fallback || ('Erreur HTTP ' + res.status);
  }

  window.RA = { h, api, ledWidget, detail };
})();
