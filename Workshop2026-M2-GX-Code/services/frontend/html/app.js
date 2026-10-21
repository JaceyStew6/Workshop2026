(function () {
  const { api, detail } = window.RA;
  const $ = (id) => document.getElementById(id);
  let token = null;
  const out = $('out');
  const show = (cls, txt) => { out.className = cls; out.textContent = txt; };

  window.RA.login($('login'), {
    title: 'Connexion', defaultUser: 'demo-user',
    onSuccess(t, info) {
      token = t;
      $('pay').hidden = !(info.perms || []).includes('payments:create');
      show('ok', $('pay').hidden ? 'Connecté, mais ce compte ne peut pas émettre de virement (habilitation payments:create absente).' : 'Connecté.');
    },
  });

  $('bq').onclick = async () => {
    const r = await api('GET', '/api/fees/quote?amount=' + encodeURIComponent($('amt').value));
    if (r.status === 0) return show('ko', 'Service injoignable.');
    show(r.ok ? 'ok' : 'ko', r.ok ? 'Frais estimés : ' + r.data.fee + ' EUR' : 'Erreur HTTP ' + r.status);
  };
  $('bp').onclick = async () => {
    const r = await api('POST', '/api/payments', { from: $('src').value, to: $('dst').value, amount: $('amt').value, idempotency_key: crypto.randomUUID() }, token);
    if (r.status === 0) return show('ko', 'Service injoignable.');
    const d = r.data || {};
    show(r.ok ? 'ok' : 'ko', r.ok ? 'Virement ' + d.status + '\nIdentifiant : ' + d.id : 'Refusé (HTTP ' + r.status + ') ' + (d.detail || d.error || ''));
  };
})();
