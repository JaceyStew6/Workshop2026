/* Back-office : utilisateurs, rôles/habilitations, visages, voyant/caméra, journal d'audit.
   Les onglets affichés dépendent des permissions portées par le jeton ; le serveur re-vérifie chaque appel
   (l'interface masque, le serveur interdit). Le jeton reste en mémoire (jamais dans le stockage du navigateur). */
(function () {
  const { h, api, ledWidget, detail } = window.RA;
  const main = document.getElementById('main');
  const consoleEl = document.getElementById('console');
  const loginEl = document.getElementById('login');
  let token = null, me = null, timers = [];

  const login = window.RA.login(loginEl, { title: 'Connexion au back-office', defaultUser: '', onSuccess: start });

  const can = (p) => me.perms.includes(p);
  const call = async (m, u, b) => {
    const r = await api(m, u, b, token);
    if (r.status === 401) { logout('Session expirée : reconnectez-vous.'); }
    return r;
  };
  const notice = (box, r, okMsg) => { box.className = 'status ' + (r.ok ? 'ok' : 'ko'); box.textContent = r.ok ? okMsg : detail(r); };

  function logout(msg) {
    timers.forEach(clearInterval); timers = []; token = me = null;
    consoleEl.hidden = true; consoleEl.replaceChildren(); loginEl.hidden = false; login.restart(msg || '', msg ? 'ko' : '');
  }

  async function start(t, info) {
    token = t; me = { user: null, role: info.role, perms: info.perms || [] };
    const who = await call('GET', '/auth/me');
    me.user = who.ok ? who.data.sub : '?';
    if (!can('backoffice:access')) { logout('Ce compte n\'a pas accès au back-office (habilitation backoffice:access absente).'); return; }
    loginEl.hidden = true; consoleEl.hidden = false;
    const tabs = [
      ['Utilisateurs', 'backoffice:users', usersTab], ['Rôles et habilitations', 'backoffice:access', rolesTab],
      ['Visages', 'backoffice:faces', facesTab], ['Voyant et caméra', 'backoffice:device', deviceTab], ['Audit', 'backoffice:audit', auditTab],
    ].filter(([, p]) => can(p));
    const body = h('div');
    const nav = h('nav', { class: 'tabs', role: 'tablist' });
    const open = (i) => {
      timers.forEach(clearInterval); timers = [];
      [...nav.children].forEach((b, j) => b.setAttribute('aria-selected', String(i === j)));
      body.replaceChildren(); tabs[i][2](body);
    };
    tabs.forEach(([name], i) => nav.append(h('button', { type: 'button', role: 'tab', onclick: () => open(i) }, name)));
    consoleEl.replaceChildren(
      h('div', { class: 'row', style: 'justify-content:space-between' },
        h('span', null, 'Connecté : ', h('strong', null, me.user), ` — rôle ${me.role}`),
        h('button', { class: 'secondary small', type: 'button', onclick: () => logout('') }, 'Se déconnecter')),
      nav, body);
    open(0);
  }

  const table = (heads, rows) => h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, heads.map((x) => h('th', null, x)))),
    h('tbody', null, rows.map((r) => h('tr', null, r.map((c) => h('td', null, c)))))));

  /* ------------------------------------------------------------------ Utilisateurs */
  async function usersTab(box, flash) {
    const msg = h('p', { class: 'status ' + (flash ? 'ok' : ''), 'aria-live': 'polite' }, flash || '');
    const [u, r] = await Promise.all([call('GET', '/auth/admin/users'), call('GET', '/auth/admin/roles')]);
    if (!u.ok) return box.replaceChildren(h('p', { class: 'ko' }, detail(u)));
    const roles = r.ok ? r.data.filter((x) => x.name !== 'probe').map((x) => x.name) : [];
    const patch = async (name, body, ok) => { const res = await call('PATCH', '/auth/admin/users/' + encodeURIComponent(name), body); notice(msg, res, ok); if (res.ok) usersTab(box, ok); return res; };
    const rows = u.data.map((x) => {
      const opts = roles.includes(x.role) ? roles : [...roles, x.role];       // le rôle machine « probe » n'est pas attribuable mais doit s'afficher
      const sel = h('select', { 'aria-label': 'Rôle de ' + x.username }, opts.map((n) => h('option', { value: n, selected: n === x.role }, n)));
      sel.disabled = x.role === 'probe' || x.username === me.user;
      sel.addEventListener('change', () => patch(x.username, { role: sel.value }, 'Rôle modifié.'));
      const face = h('input', { type: 'checkbox', checked: x.face_required, 'aria-label': 'Visage exigé pour ' + x.username });
      face.disabled = x.role === 'probe' || x.username === me.user;
      face.addEventListener('change', async () => { const res = await patch(x.username, { face_required: face.checked }, 'Exigence faciale mise à jour.'); if (!res.ok) face.checked = !face.checked; });
      const act = h('input', { type: 'checkbox', checked: x.active, 'aria-label': 'Actif : ' + x.username });
      act.disabled = x.role === 'probe' || x.username === me.user;
      act.addEventListener('change', async () => { const res = await patch(x.username, { active: act.checked }, 'Compte mis à jour.'); if (!res.ok) act.checked = !act.checked; });
      const reset = h('button', { class: 'secondary small', type: 'button', disabled: x.role === 'probe', onclick: async () => {
        const pw = window.prompt('Nouveau mot de passe pour ' + x.username + ' (12 caractères minimum) :');
        if (pw) patch(x.username, { password: pw }, 'Mot de passe réinitialisé.');
      } }, 'Réinitialiser le mot de passe');
      return [x.username, sel, face, String(x.faces), act, reset];
    });
    const nu = h('input', { maxlength: 64, 'aria-label': 'Nouvel identifiant' }), np = h('input', { type: 'password', maxlength: 128, autocomplete: 'new-password', 'aria-label': 'Mot de passe' });
    const nr = h('select', { 'aria-label': 'Rôle' }, roles.map((n) => h('option', { value: n }, n)));
    const add = h('button', { type: 'button', onclick: async () => {
      const res = await call('POST', '/auth/admin/users', { username: nu.value.trim(), password: np.value, role: nr.value });
      notice(msg, res, 'Utilisateur créé. Inscrivez son visage (onglet Visages) pour activer l\'exigence faciale.'); if (res.ok) usersTab(box);
    } }, 'Créer');
    box.replaceChildren(h('div', { class: 'card' }, h('h2', null, 'Utilisateurs'),
      table(['Identifiant', 'Rôle', 'Visage exigé', 'Visages', 'Actif', ''], rows),
      h('p', { class: 'muted' }, 'Exiger le visage n\'est possible qu\'après l\'inscription d\'un visage (sinon le compte serait verrouillé). Vous ne pouvez pas réduire vos propres droits. Un jeton déjà émis reste valable jusqu\'à 15 minutes, mais les actions d\'administration vérifient le compte en base à chaque appel.')),
    h('div', { class: 'card' }, h('h3', null, 'Nouvel utilisateur'),
      h('div', { class: 'row' }, h('div', { class: 'grow' }, nu), h('div', { class: 'grow' }, np), h('div', null, nr), add),
      h('p', { class: 'muted' }, 'Mot de passe : 12 caractères minimum.')), msg);
  }

  /* ------------------------------------------------------------------ Rôles */
  async function rolesTab(box, flash) {
    const msg = h('p', { class: 'status ' + (flash ? 'ok' : ''), 'aria-live': 'polite' }, flash || '');
    const [r, p] = await Promise.all([call('GET', '/auth/admin/roles'), call('GET', '/auth/admin/permissions')]);
    if (!r.ok || !p.ok) return box.replaceChildren(h('p', { class: 'ko' }, detail(r.ok ? p : r)));
    const editable = can('backoffice:roles');
    const rows = r.data.map((x) => [x.name + (x.system ? ' (système)' : ''), x.description, x.permissions.join(', ') || '—', String(x.users),
      editable && !x.system ? h('button', { class: 'danger small', type: 'button', onclick: async () => {
        if (!window.confirm('Supprimer le rôle ' + x.name + ' ?')) return;
        const res = await call('DELETE', '/auth/admin/roles/' + encodeURIComponent(x.name)); notice(msg, res, ''); if (res.ok) rolesTab(box, 'Rôle supprimé.');
      } }, 'Supprimer') : '']);
    const name = h('input', { maxlength: 32, placeholder: 'ex. auditeur', 'aria-label': 'Nom du rôle' }), desc = h('input', { maxlength: 200, 'aria-label': 'Description' });
    const checks = p.data.map((x) => {
      const cb = h('input', { type: 'checkbox', value: x.name, disabled: !me.perms.includes(x.name) });
      return h('label', null, cb, h('span', null, x.name, h('span', { class: 'muted' }, ' — ' + x.description)));
    });
    const create = h('button', { type: 'button', onclick: async () => {
      const perms = checks.map((l) => l.firstChild).filter((c) => c.checked).map((c) => c.value);
      const res = await call('POST', '/auth/admin/roles', { name: name.value.trim(), description: desc.value, permissions: perms });
      notice(msg, res, ''); if (res.ok) rolesTab(box, 'Rôle créé.');
    } }, 'Créer le rôle');
    box.replaceChildren(...[h('div', { class: 'card' }, h('h2', null, 'Rôles et habilitations'),
      table(['Rôle', 'Description', 'Permissions', 'Utilisateurs', ''], rows),
      h('p', { class: 'muted' }, 'Les rôles système ne sont pas modifiables. Un rôle ne peut recevoir que des permissions que vous détenez vous-même (pas d\'escalade de privilèges).')),
    editable ? h('div', { class: 'card' }, h('h3', null, 'Nouveau rôle'), h('label', null, 'Nom'), name, h('label', null, 'Description'), desc,
      h('h3', null, 'Permissions'), h('div', { class: 'perms' }, checks), create) : null, msg].filter(Boolean));
  }

  /* ------------------------------------------------------------------ Visages */
  async function facesTab(box, flash) {
    const msg = h('p', { class: 'status ' + (flash ? 'ok' : ''), 'aria-live': 'polite' }, flash || '');
    const f = await call('GET', '/gate/faces');
    if (!f.ok) return box.replaceChildren(h('p', { class: 'ko' }, detail(f)));
    const rows = f.data.map((x) => [x.username, x.label, String(x.samples), x.created_by, x.created_at.slice(0, 16).replace('T', ' '),
      h('button', { class: 'danger small', type: 'button', onclick: async () => {
        if (!window.confirm('Supprimer cette empreinte faciale ?')) return;
        const res = await call('DELETE', '/gate/faces/' + x.id); notice(msg, res, ''); if (res.ok) facesTab(box, 'Empreinte supprimée.');
      } }, 'Supprimer')]);
    const who = h('input', { maxlength: 64, 'aria-label': 'Utilisateur à inscrire' }), label = h('input', { maxlength: 60, value: 'visage principal', 'aria-label': 'Libellé' });
    const cam = h('span', { class: 'pill off' }, 'Caméra : éteinte');
    const go = h('button', { type: 'button', onclick: async () => {
      go.disabled = true; cam.className = 'pill on'; cam.textContent = 'Caméra : ALLUMÉE';
      msg.className = 'status'; msg.textContent = 'Placez UNE seule personne face à la caméra, immobile, bien éclairée…';
      const r = await call('POST', '/gate/faces/enroll', { username: who.value.trim(), label: label.value });
      if (!r.ok) { go.disabled = false; cam.className = 'pill off'; cam.textContent = 'Caméra : éteinte'; return notice(msg, r, ''); }
      const t = setInterval(async () => {
        const s = await call('GET', '/gate/faces/enroll/' + r.data.job_id);
        if (!s.ok || s.data.state === 'running') return;
        clearInterval(t); go.disabled = false; cam.className = 'pill off'; cam.textContent = 'Caméra : éteinte';
        const why = { no_face: 'aucun visage détecté', multiple_faces: 'plusieurs visages dans le champ', too_small: 'visage trop petit : rapprochez-vous',
          inconsistent: 'images incohérentes (une seule personne, sans bouger)', partial: 'trop peu d\'images exploitables', timeout: 'délai dépassé', agent_unavailable: 'agent caméra injoignable (lancez host-agent/run-agent.ps1)' };
        if (s.data.state === 'done') facesTab(box, 'Visage inscrit (' + s.data.captured + ' images). L\'exigence faciale est activée pour ce compte.');
        else { msg.className = 'status ko'; msg.textContent = 'Inscription échouée : ' + (why[s.data.reason] || s.data.reason); }
      }, 700);
    } }, 'Inscrire un visage');
    box.replaceChildren(h('div', { class: 'card' }, h('h2', null, 'Visages enregistrés'),
      table(['Utilisateur', 'Libellé', 'Images', 'Inscrit par', 'Date', ''], rows),
      h('p', { class: 'muted' }, 'Seule une empreinte numérique (128 nombres, chiffrée) est conservée : jamais la photo.')),
    h('div', { class: 'card' }, h('h3', null, 'Inscrire un visage (caméra du PC Hôte)'),
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('label', null, 'Utilisateur'), who), h('div', { class: 'grow' }, h('label', null, 'Libellé'), label), go, cam),
      h('p', { class: 'muted' }, 'La personne à inscrire doit être physiquement devant le poste. Une dernière empreinte ne peut pas être supprimée tant que l\'exigence faciale est active.')), msg);
  }

  /* ------------------------------------------------------------------ Dispositif */
  async function deviceTab(box) {
    const led = ledWidget(), msg = h('p', { class: 'status', 'aria-live': 'polite' });
    const info = h('div', { class: 'mono' });
    const refresh = async () => {
      const r = await call('GET', '/gate/device'); if (!r.ok) return;
      const d = r.data; led.set(d.led.pattern);
      info.textContent = [
        `Voyant ESP8266 : ${d.device.online ? 'EN LIGNE' : 'hors ligne'}${d.device.last_seen_s != null ? ` (dernier contact il y a ${d.device.last_seen_s} s, ${d.device.ip})` : ' (jamais vu)'}`,
        `Agent caméra : ${d.agent.ok ? 'joignable — caméra ' + (d.agent.camera_on ? 'ALLUMÉE' : 'éteinte') + ` (${d.agent.backend})` : 'INJOIGNABLE'}`,
        `Poste : ${d.busy ? 'occupé (' + d.busy + ')' : 'libre'}`].join('\n');
    };
    const test = (pattern, label) => h('button', { class: 'secondary small', type: 'button', onclick: async () => {
      const r = await call('POST', '/gate/device/test', { pattern, seconds: 5 }); notice(msg, r, `Test « ${label} » envoyé (5 s) : regardez la LED.`); refresh();
    } }, label);
    box.replaceChildren(h('div', { class: 'card' }, h('h2', null, 'Voyant bicolore et caméra'),
      h('div', { class: 'row' }, h('span', null, 'Voyant virtuel :'), led.el), info,
      h('h3', null, 'Tester la LED physique (5 s, seulement hors identification)'),
      h('div', { class: 'row' }, test('green_blink', 'Vert clignotant'), test('green_solid', 'Vert fixe'), test('red_blink', 'Rouge clignotant'), test('red_solid', 'Rouge fixe'), test('off', 'Éteint')),
      h('h3', null, 'Urgence'),
      h('button', { class: 'danger small', type: 'button', onclick: async () => { const r = await call('POST', '/gate/camera/off'); notice(msg, r, 'Caméra et voyant forcés à l\'arrêt.'); refresh(); } }, 'Forcer l\'extinction de la caméra'),
      msg));
    refresh(); timers.push(setInterval(refresh, 1500));
  }

  /* ------------------------------------------------------------------ Audit */
  async function auditTab(box) {
    const r = await call('GET', '/auth/admin/audit?limit=200');
    if (!r.ok) return box.replaceChildren(h('p', { class: 'ko' }, detail(r)));
    box.replaceChildren(h('div', { class: 'card' }, h('h2', null, 'Journal d\'audit'),
      table(['Date (UTC)', 'Acteur', 'Action', 'Cible', 'Détail', 'IP'],
        r.data.map((x) => [x.ts.slice(0, 19).replace('T', ' '), x.actor, x.action, x.target, JSON.stringify(x.detail), x.ip])),
      h('p', { class: 'muted' }, 'Aucune donnée biométrique dans ce journal : score de similarité arrondi, motif de refus, identifiant.')));
  }
})();
