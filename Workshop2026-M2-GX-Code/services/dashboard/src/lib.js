// Logique pure du dashboard (testée par vitest) : phases avant / pendant / après et statistiques associées.
export const median = (xs) => {
  if (!xs.length) return null
  const s = [...xs].sort((a, b) => a - b)
  const m = Math.floor(s.length / 2)
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

export function phaseOf(state) {
  if (state?.open_incidents?.length) return 'pendant'
  if (state?.last_incident) return 'apres'
  return 'avant'
}

// Latence perçue par un client : avant l'incident (médiane des 60 s précédentes), pendant (maximum), après (médiane des 30 dernières secondes)
export function phaseStats(state) {
  const samples = state?.samples ?? []
  const inc = state?.open_incidents?.[0] ?? state?.last_incident
  if (!inc || !samples.length) return { avant: median(samples.slice(-20).map((s) => s.ms)), pendant: null, apres: null }
  const start = inc.received_at
  const end = inc.finished_at ?? Infinity
  const before = samples.filter((s) => s.ts < start && s.ts > start - 60).map((s) => s.ms)
  const during = samples.filter((s) => s.ts >= start && s.ts <= end).map((s) => s.ms)
  const after = inc.finished_at ? samples.filter((s) => s.ts > end).slice(-15).map((s) => s.ms) : []
  return { avant: median(before), pendant: during.length ? Math.max(...during) : null, apres: median(after) }
}

export const STATE_LABEL = {
  up: 'OPÉRATIONNEL', degraded: 'DÉGRADÉ', down: 'HORS SERVICE',
}
export const INCIDENT_LABEL = {
  DETECTED: 'Anomalie détectée', DECIDING: 'Décision', REMEDIATING: 'Remédiation en cours', VERIFYING: 'Vérification par transaction',
  RECOVERED: 'Service rétabli', CONTAINED: 'Compromission contenue', ESCALATED: 'Escalade humaine requise',
}
