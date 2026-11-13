import { describe, expect, it } from 'vitest'
import { DEFAULT_ACTOR, isValidActor, validateActor } from './actor'

describe('actor rule (contract v2 §7)', () => {
  it('accepts printable ASCII up to 64 characters, trimmed', () => {
    expect(validateActor('  Anna K.  ')).toEqual({ ok: true, actor: 'Anna K.' })
    expect(validateActor('x'.repeat(64))).toEqual({ ok: true, actor: 'x'.repeat(64) })
  })

  it('defaults a blank name', () => {
    for (const raw of [undefined, null, '', '   ']) {
      expect(validateActor(raw)).toEqual({ ok: true, actor: DEFAULT_ACTOR })
    }
  })

  // These broke every API call of the session: header values are byte strings.
  it('refuses names outside printable ASCII and suggests a spelling', () => {
    const cases: [string, string][] = [
      ['Łukasz', 'Lukasz'],
      ['Michał', 'Michal'],
      ['Zoë', 'Zoe'],
    ]
    for (const [name, suggestion] of cases) {
      const r = validateActor(name)
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.message).toContain(`"${suggestion}"`)
    }
    const emoji = validateActor('🦊')
    expect(emoji.ok).toBe(false)
    if (!emoji.ok) expect(emoji.message).not.toContain('Try')
  })

  it('refuses control characters, over-long names and non-strings', () => {
    expect(validateActor('a\r\nX-Injected: 1').ok).toBe(false)
    expect(validateActor('a\tb').ok).toBe(false)
    expect(validateActor('x'.repeat(65)).ok).toBe(false)
    expect(validateActor(42).ok).toBe(false)
    expect(validateActor({}).ok).toBe(false)
  })

  it('isValidActor matches the rule', () => {
    expect(isValidActor('household')).toBe(true)
    expect(isValidActor('')).toBe(false)
    expect(isValidActor('Łukasz')).toBe(false)
  })
})
