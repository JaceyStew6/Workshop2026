import { describe, expect, it } from 'vitest'
import { median, phaseOf, phaseStats } from './lib.js'

describe('phaseOf', () => {
  it('avant : aucun incident', () => expect(phaseOf({ open_incidents: [], last_incident: null })).toBe('avant'))
  it('pendant : incident ouvert', () => expect(phaseOf({ open_incidents: [{}], last_incident: {} })).toBe('pendant'))
  it('après : incident terminé', () => expect(phaseOf({ open_incidents: [], last_incident: { state: 'RECOVERED' } })).toBe('apres'))
})

describe('phaseStats', () => {
  const samples = [
    ...[100, 102, 98].map((ms, i) => ({ ts: 940 + i * 5, ms })),   // avant (incident reçu à 1000)
    ...[900, 3000, 2500].map((ms, i) => ({ ts: 1000 + i * 5, ms })), // pendant
    ...[60, 55, 58].map((ms, i) => ({ ts: 1040 + i * 5, ms })),     // après (fin à 1030)
  ]
  it('calcule avant / pendant / après', () => {
    const st = phaseStats({ samples, open_incidents: [], last_incident: { received_at: 1000, finished_at: 1030 } })
    expect(st.avant).toBe(100)
    expect(st.pendant).toBe(3000)
    expect(st.apres).toBe(58)
  })
  it("pendant l'incident, « après » n'existe pas encore", () => {
    const st = phaseStats({ samples, open_incidents: [{ received_at: 1000, finished_at: null }], last_incident: null })
    expect(st.apres).toBeNull()
  })
  it('médiane vide', () => expect(median([])).toBeNull())
})
