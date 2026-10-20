import React, { useEffect, useMemo, useState } from 'react'
import { INCIDENT_LABEL, STATE_LABEL, phaseOf, phaseStats } from './lib.js'

const fmtMs = (v) => (v == null ? '—' : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`)
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString('fr-FR')

const TONE = {
  up: 'bg-emerald-100 text-emerald-900 border-emerald-400 dark:bg-emerald-950 dark:text-emerald-100 dark:border-emerald-700',
  degraded: 'bg-amber-100 text-amber-900 border-amber-400 dark:bg-amber-950 dark:text-amber-100 dark:border-amber-700',
  down: 'bg-red-100 text-red-900 border-red-400 dark:bg-red-950 dark:text-red-100 dark:border-red-700',
}
const FINAL_TONE = {
  RECOVERED: TONE.up, CONTAINED: TONE.degraded, ESCALATED: TONE.down,
}

function useState1s() {
  const [state, setState] = useState(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const r = await fetch('/v1/state?history=300')
        if (!r.ok) throw new Error(String(r.status))
        const d = await r.json()
        if (alive) { setState(d); setError(false) }
      } catch { if (alive) setError(true) }
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => { alive = false; clearInterval(id) }
  }, [])
  return { state, error }
}

// Courbe de latence en SVG pur : la couleur ET une légende textuelle portent l'état (pas la couleur seule).
function LatencyChart({ samples, incident }) {
  const W = 720, H = 150, P = 24
  if (!samples.length) return <div className="h-[150px] grid place-items-center text-sm opacity-60">En attente de mesures…</div>
  const t0 = samples[0].ts, t1 = samples[samples.length - 1].ts || t0 + 1
  const maxMs = Math.max(500, ...samples.map((s) => s.ms))
  const x = (t) => P + ((t - t0) / Math.max(1, t1 - t0)) * (W - 2 * P)
  const y = (ms) => H - P - (Math.min(ms, maxMs) / maxMs) * (H - 2 * P)
  const color = { up: '#059669', degraded: '#d97706', down: '#dc2626' }
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Latence perçue par un client sur les 5 dernières minutes" className="w-full">
      <line x1={P} x2={W - P} y1={y(500)} y2={y(500)} stroke="currentColor" strokeDasharray="4 4" opacity="0.35" />
      <text x={W - P} y={y(500) - 4} textAnchor="end" fontSize="10" fill="currentColor" opacity="0.6">seuil « dégradé » 500 ms</text>
      {incident && <rect x={x(incident.received_at)} y={P / 2} width={Math.max(2, x(incident.finished_at ?? t1) - x(incident.received_at))} height={H - P * 1.5} fill="currentColor" opacity="0.08" />}
      <polyline fill="none" stroke="currentColor" strokeWidth="1" opacity="0.25" points={samples.map((s) => `${x(s.ts)},${y(s.ms)}`).join(' ')} />
      {samples.map((s, i) => <circle key={i} cx={x(s.ts)} cy={y(s.ms)} r="2.5" fill={color[s.state]}><title>{`${clock(s.ts)} · ${STATE_LABEL[s.state]} · ${fmtMs(s.ms)}`}</title></circle>)}
      <text x={P} y={H - 6} fontSize="10" fill="currentColor" opacity="0.6">{clock(t0)}</text>
      <text x={W - P} y={H - 6} textAnchor="end" fontSize="10" fill="currentColor" opacity="0.6">{clock(t1)}</text>
    </svg>
  )
}

function Phase({ title, active, value, hint }) {
  return (
    <div className={`rounded-lg border p-3 ${active ? 'border-sky-500 ring-2 ring-sky-300 dark:ring-sky-700' : 'border-slate-300 dark:border-slate-700 opacity-80'}`}>
      <div className="text-xs uppercase tracking-wide opacity-70">{title}{active ? ' · en cours' : ''}</div>
      <div className="text-2xl font-semibold tabular-nums">{fmtMs(value)}</div>
      <div className="text-xs opacity-70">{hint}</div>
    </div>
  )
}

function Timeline({ incident }) {
  const t0 = incident.received_at
  const events = [
    ...incident.transitions.map((t) => ({ ts: t.ts, label: INCIDENT_LABEL[t.state] ?? t.state, detail: t.why, kind: 'state', state: t.state })),
    ...incident.steps.map((s) => ({ ts: s.ts, label: `${s.action}${s.ip ? ` ${s.ip}` : ''}`, detail: s.detail, kind: 'action', ok: s.ok })),
  ].sort((a, b) => a.ts - b.ts)
  return (
    <ol className="space-y-1 text-sm">
      {events.map((e, i) => (
        <li key={i} className="flex gap-3 items-baseline">
          <span className="w-14 shrink-0 text-right tabular-nums opacity-60">+{(e.ts - t0).toFixed(1)} s</span>
          <span className={e.kind === 'action' ? 'font-mono' : 'font-semibold'}>
            {e.kind === 'action' && <span aria-label={e.ok ? 'réussi' : 'échoué'}>{e.ok ? '✓ ' : '✗ '}</span>}{e.label}
          </span>
          <span className="opacity-70 truncate" title={e.detail}>{e.detail}</span>
        </li>
      ))}
    </ol>
  )
}

function Verification({ v }) {
  if (!v) return null
  return (
    <div className="mt-3">
      <h4 className="text-sm font-semibold mb-1">Vérification transactionnelle {v.ok ? '— réussie' : '— en cours / échec'}</h4>
      <ul className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
        {v.steps.map((s, i) => (
          <li key={i} className={`rounded border p-2 ${s.ok ? TONE.up : TONE.down}`}>
            <div className="font-semibold">{s.ok ? '✓' : '✗'} {s.step}</div>
            <div className="tabular-nums">{s.ms} ms</div>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function App() {
  const { state, error } = useState1s()
  const phase = phaseOf(state)
  const stats = useMemo(() => phaseStats(state), [state])
  const incident = state?.open_incidents?.[0] ?? state?.last_incident
  const cur = state?.current

  return (
    <main className="max-w-5xl mx-auto px-4 py-5 space-y-4">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-xl font-bold">RESILIENCE-ALPHA · Supervision</h1>
        <span className="text-xs opacity-70">Plateforme de paiement fictive · mise à jour chaque seconde{error ? ' · LIAISON PERDUE avec le moteur' : ''}</span>
      </header>

      <section aria-live="polite" className={`rounded-xl border-2 p-4 flex flex-wrap items-center justify-between gap-3 ${cur ? TONE[cur.state] : 'border-slate-300'}`}>
        <div>
          <div className="text-xs uppercase tracking-wide opacity-70">État du service vu par un client</div>
          <div className="text-3xl font-extrabold">{cur ? STATE_LABEL[cur.state] : 'EN ATTENTE'}</div>
        </div>
        <div className="text-right text-sm tabular-nums">
          <div>HTTP {cur?.status || '—'} · {fmtMs(cur?.ms)}</div>
          <div className="opacity-70">sonde : devis public via le WAF</div>
        </div>
      </section>

      <section className="grid grid-cols-1 sm:grid-cols-3 gap-3" aria-label="Latence avant, pendant et après l'incident">
        <Phase title="Avant" active={phase === 'avant'} value={stats.avant} hint="médiane, 60 s avant l'alerte" />
        <Phase title="Pendant" active={phase === 'pendant'} value={stats.pendant} hint="pire latence pendant l'incident" />
        <Phase title="Après" active={phase === 'apres'} value={stats.apres} hint="médiane, après rétablissement" />
      </section>

      <section className="rounded-xl border border-slate-300 dark:border-slate-700 p-3">
        <LatencyChart samples={state?.samples ?? []} incident={incident} />
        <div className="flex gap-4 text-xs mt-1 opacity-80" aria-hidden="false">
          <span>● vert : opérationnel</span><span>● orange : dégradé</span><span>● rouge : hors service</span>
        </div>
      </section>

      <section className="rounded-xl border border-slate-300 dark:border-slate-700 p-4">
        {!incident ? (
          <p className="text-sm opacity-80">Aucun incident. Le détecteur surveille la plateforme.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h2 className="font-semibold">Incident {incident.incident_id}</h2>
              <span className={`rounded-full border px-3 py-1 text-sm font-semibold ${FINAL_TONE[incident.state] ?? TONE.degraded}`}>
                {INCIDENT_LABEL[incident.state] ?? incident.state}{incident.duration_s != null ? ` · ${incident.duration_s} s` : ''}
              </span>
            </div>
            <p className="text-xs opacity-70 mb-2">
              Classe : {incident.suspected_class} · score {incident.anomaly_score} · cible {incident.target_service} · {clock(incident.received_at)}
            </p>
            <Timeline incident={incident} />
            <Verification v={incident.verification} />
          </>
        )}
      </section>
    </main>
  )
}
