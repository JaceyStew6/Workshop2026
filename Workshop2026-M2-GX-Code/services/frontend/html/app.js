  let token = null;
  const out = document.getElementById('out');
  const show = (cls, txt) => { out.className = cls; out.textContent = txt; };
  const j = (m, url, body, auth) => fetch(url, { method:m, headers:{ 'content-type':'application/json', ...(auth?{authorization:'Bearer '+token}:{}) }, body: body?JSON.stringify(body):undefined });
  document.getElementById('bl').onclick = async () => {
    try {
      const r = await j('POST', '/auth/token', { username:u.value, password:p.value });
      if (!r.ok) return show('ko', 'Connexion refusée (HTTP ' + r.status + ')');
      token = (await r.json()).access_token; document.getElementById('pay').hidden = false; show('ok', 'Connecté.');
    } catch { show('ko', 'Service injoignable.'); }
  };
  document.getElementById('bq').onclick = async () => {
    try { const r = await fetch('/api/fees/quote?amount=' + encodeURIComponent(amt.value)); show(r.ok?'ok':'ko', r.ok ? 'Frais estimés : ' + (await r.json()).fee + ' EUR' : 'Erreur HTTP ' + r.status); }
    catch { show('ko', 'Service injoignable.'); }
  };
  document.getElementById('bp').onclick = async () => {
    try {
      const r = await j('POST', '/api/payments', { from:src.value, to:dst.value, amount:amt.value, idempotency_key: crypto.randomUUID() }, true);
      const d = await r.json().catch(() => ({}));
      show(r.ok?'ok':'ko', r.ok ? 'Virement ' + d.status + '\nIdentifiant : ' + d.id : 'Refusé (HTTP ' + r.status + ') ' + (d.detail||d.error||''));
    } catch { show('ko', 'Service injoignable.'); }
  };
