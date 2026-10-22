/* Connexion en trois étapes : identifiant -> reconnaissance faciale (caméra du PC Hôte) -> mot de passe.
   Les comptes d'administration et les comptes machine passent directement de l'identifiant au mot de passe.
   Toute la décision est prise côté serveur (face-gate / auth-service) ; ce composant ne fait qu'afficher l'état. */
(function () {
  const { h, api, ledWidget, detail } = window.RA;

  window.RA.login = function mountLogin(container, { title = 'Connexion', defaultUser = '', onSuccess }) {
    const led = ledWidget();
    const cam = h('span', { class: 'pill off' }, 'Caméra : éteinte');
    const status = h('p', { class: 'status', 'aria-live': 'polite' });
    const user = h('input', { id: 'u', autocomplete: 'username', value: defaultUser, maxlength: 64 });
    const pass = h('input', { id: 'p', type: 'password', autocomplete: 'current-password', maxlength: 128 });
    const passRow = h('div', { hidden: true }, h('label', { for: 'p' }, 'Mot de passe'), pass);
    const go = h('button', { id: 'bl', type: 'submit' }, 'Continuer');
    const cancel = h('button', { type: 'button', class: 'secondary', hidden: true }, 'Annuler');
    const form = h('form', { novalidate: true }, h('label', { for: 'u' }, 'Identifiant'), user, passRow,
      h('div', { class: 'row' }, go, cancel), status);
    container.replaceChildren(h('div', { class: 'row', style: 'justify-content:space-between' }, h('h2', null, title),
      h('span', { class: 'row', style: 'gap:10px' }, cam, led.el)), form);

    let sid = null, poller = null, ticker = null, mode = 'identify', face = false;

    const say = (msg, cls) => { status.className = 'status ' + (cls || ''); status.textContent = msg; };
    const stop = () => { clearInterval(poller); clearInterval(ticker); poller = ticker = null; };
    const camera = (on, extra) => { cam.className = 'pill ' + (on ? 'on' : 'off'); cam.textContent = on ? 'Caméra : ALLUMÉE' + (extra || '') : 'Caméra : éteinte'; };
    const lock = (v) => { user.disabled = v; pass.disabled = v; go.disabled = v; };

    /* Retour à l'étape 1 : identifiant et mot de passe vidés. */
    function restart(msg, cls) {
      stop(); sid = null; mode = 'identify'; face = false;
      user.value = ''; pass.value = ''; passRow.hidden = true; user.readOnly = false; cancel.hidden = true;
      go.textContent = 'Continuer'; lock(false); camera(false); say(msg || '', cls); user.focus();
    }

    /* Compte à rebours affiché dans le message, qui exécute `then` à zéro. */
    function countdown(seconds, build, then) {
      clearInterval(ticker);
      let left = Math.max(1, Math.ceil(seconds));
      say(build(left), 'ko');
      ticker = setInterval(() => { left -= 1; if (left <= 0) { clearInterval(ticker); then && then(); } else say(build(left), 'ko'); }, 1000);
    }

    function blocked(s) {
      lock(true); stop();
      countdown(s, (n) => `Trop d'échecs : identification bloquée. Nouvelle tentative possible dans ${Math.floor(n / 60)} min ${String(n % 60).padStart(2, '0')} s.`,
        () => restart('Vous pouvez recommencer.'));
    }

    async function poll() {
      const r = await api('GET', '/gate/session/' + sid);
      if (r.status === 404) return restart('Session expirée : recommencez.', 'ko');
      if (!r.ok) return;
      const st = r.data;
      led.set(st.led && st.led.pattern);
      switch (st.state) {
        case 'scanning':
          camera(true); say('Reconnaissance faciale en cours… regardez la caméra du poste.'); break;
        case 'awaiting_password':
          if (mode !== 'password') {
            mode = 'password'; passRow.hidden = false; user.readOnly = true; go.textContent = 'Se connecter'; cancel.hidden = false; lock(false); user.disabled = false;
            pass.focus();
          }
          camera(true);
          say(`Visage reconnu. Saisissez votre mot de passe (${st.expires_in_s} s).`, 'ok'); break;
        case 'verifying':
          say('Vérification…'); break;
        case 'denied':
          stop(); { const secs = st.retry_in_s || 30; const s = sid;
            user.value = ''; pass.value = ''; passRow.hidden = true; cancel.hidden = true; lock(true); mode = 'identify';
            let left = secs; camera(true, ` (extinction dans ${left} s)`);
            const msg = () => (st.blocked_s ? `Visage non reconnu. Identification bloquée 5 minutes.` : `Visage non reconnu. Il reste ${st.attempts_left} essai.`)
              + ` Voyant rouge : patientez ${left} s.`;
            say(msg(), 'ko');
            ticker = setInterval(async () => {
              left -= 1; camera(true, ` (extinction dans ${Math.max(left, 0)} s)`); say(msg(), 'ko');
              if (left <= 0) {
                clearInterval(ticker); const f = await api('GET', '/gate/session/' + s);
                led.set(f.data && f.data.led && f.data.led.pattern);
                st.blocked_s ? blocked(Math.max(st.blocked_s - secs, 5)) : restart('Caméra éteinte. Vous pouvez ressaisir votre identifiant.');
              }
            }, 1000); }
          break;
        case 'holding':
          stop(); { let left = st.retry_in_s || 10; lock(true);
            ticker = setInterval(() => { left -= 1; say(`Mot de passe incorrect : recommencez l'identification dans ${Math.max(left, 0)} s.`, 'ko'); if (left <= 0) { clearInterval(ticker); led.set('off'); restart('Recommencez : saisissez votre identifiant.'); } }, 1000); }
          break;
        case 'closed': {
          const fin = st.final;
          if (fin === 'error') restart('Le service de reconnaissance faciale est indisponible (caméra non joignable). Contactez un administrateur.', 'ko');
          else if (fin === 'timeout') restart('Délai dépassé : recommencez l\'identification.', 'ko');
          else if (fin === 'cancelled') restart('Identification annulée.');
          else if (fin !== 'success') restart('', '');
          break;
        }
        default: break;
      }
    }

    async function onGo() {
      if (mode === 'identify') {
        const name = user.value.trim();
        if (!name) return say('Saisissez votre identifiant.', 'ko');
        lock(true); say('Vérification…');
        const r = await api('POST', '/gate/identify', { username: name });
        lock(false);
        if (r.status === 429 && r.data && r.data.code === 'blocked') { user.value = ''; return blocked(r.data.blocked_s); }
        if (r.status === 423) return say((r.data && r.data.detail) || 'Caméra occupée, patientez.', 'ko');
        if (!r.ok) return say(detail(r, 'Service injoignable.'), 'ko');
        if (!r.data.face_required) {                       // compte sans exigence faciale : mot de passe seulement
          face = false; mode = 'password'; passRow.hidden = false; user.readOnly = true; go.textContent = 'Se connecter';
          cancel.hidden = false; say(''); return pass.focus();
        }
        face = true; sid = r.data.session_id; lock(true); cancel.hidden = false; cancel.disabled = false; camera(true);
        say('Reconnaissance faciale en cours… regardez la caméra du poste.');
        poller = setInterval(poll, 700); poll();
        return;
      }
      /* mode === 'password' */
      if (!pass.value) return say('Saisissez votre mot de passe.', 'ko');
      go.disabled = true;
      if (!face) {
        const r = await api('POST', '/auth/token', { username: user.value.trim(), password: pass.value });
        go.disabled = false;
        if (!r.ok) { pass.value = ''; return say(r.status === 429 ? 'Trop de tentatives, réessayez plus tard.' : r.status === 0 ? 'Service injoignable.' : 'Identifiants invalides.', 'ko'); }
        const out = r.data; restart(''); return onSuccess(out.access_token, out);
      }
      const r = await api('POST', '/gate/password', { session_id: sid, password: pass.value });
      if (r.ok) {
        stop(); const out = r.data; const who = user.value.trim();
        camera(false); led.set('green_solid'); restart(`Connecté (${who}). Voyant vert fixe 30 s.`, 'ok'); led.set('green_solid');
        setTimeout(() => led.set('off'), 30000);
        return onSuccess(out.access_token, out);
      }
      pass.value = '';
      if (r.status === 401 && r.data && r.data.restart) {   // la suite est pilotée par le sondage de session (état « holding »)
        stop(); user.value = ''; passRow.hidden = true; cancel.hidden = true; lock(true); camera(false); led.set('red_blink');
        let left = r.data.retry_in_s || 10;
        countdown(left, (n) => `Mot de passe incorrect. Voyant rouge clignotant : recommencez l'identification dans ${n} s.`,
          () => { led.set('off'); restart('Recommencez : saisissez votre identifiant.'); });
        return;
      }
      go.disabled = false;
      if (r.status === 404 || r.status === 409) return restart('Session expirée : recommencez.', 'ko');
      say(detail(r), 'ko');
    }

    form.addEventListener('submit', (e) => { e.preventDefault(); if (!go.disabled) onGo(); });
    cancel.addEventListener('click', async () => {
      if (sid) await api('POST', '/gate/cancel', { session_id: sid });
      led.set('off'); restart('Identification annulée.');
    });
    window.addEventListener('pagehide', () => { if (sid && navigator.sendBeacon) navigator.sendBeacon('/gate/cancel', new Blob([JSON.stringify({ session_id: sid })], { type: 'application/json' })); });
    return { restart };
  };
})();
