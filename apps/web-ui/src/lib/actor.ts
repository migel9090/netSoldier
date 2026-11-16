/**
 * The sign-in name ("actor") rule, shared by the login endpoint and its tests.
 *
 * The name is stamped on every upstream request as X-Netsoldier-Actor and
 * recorded in the killswitch audit log. HTTP header values are byte strings,
 * so a name outside Latin-1 ("Łukasz") used to make Node's fetch throw on
 * every API call of that session. Contract v2 §7 settles it: printable ASCII,
 * 1–64 characters, enforced once at sign-in.
 *
 * The killswitch also keeps a few names for its own transitions and answers
 * 400 to every approve, reject and revert signed with one of them, so they
 * are refused here too: a session under such a name could look at the
 * approval page but never act on it.
 */

export const ACTOR_MAX_LENGTH = 64

/** Used when the sign-in form leaves the name blank. */
export const DEFAULT_ACTOR = 'household'

const PRINTABLE_ASCII = /^[\x20-\x7e]+$/

/**
 * The killswitch's own actors (actions.IsSystemActor, compared without
 * regard to case): the policy, the TTL reaper, reconciliation, results the
 * network agent reported, and capacity eviction.
 */
export const RESERVED_ACTORS = ['auto-policy', 'ttl', 'reconcile', 'netagent', 'system'] as const

export function isReservedActor(actor: string): boolean {
  return (RESERVED_ACTORS as readonly string[]).includes(actor.toLowerCase())
}

/** True when `actor` may be sent as a header value and written to the audit log. */
export function isValidActor(actor: string): boolean {
  return (
    actor.length >= 1 &&
    actor.length <= ACTOR_MAX_LENGTH &&
    PRINTABLE_ASCII.test(actor) &&
    !isReservedActor(actor)
  )
}

export type ActorResult = { ok: true; actor: string } | { ok: false; message: string }

/** Validates the name typed at sign-in; blank means {@link DEFAULT_ACTOR}. */
export function validateActor(raw: unknown): ActorResult {
  if (raw === undefined || raw === null) return { ok: true, actor: DEFAULT_ACTOR }
  if (typeof raw !== 'string') return { ok: false, message: 'Your name must be text.' }

  const actor = raw.trim()
  if (actor === '') return { ok: true, actor: DEFAULT_ACTOR }

  if (!PRINTABLE_ASCII.test(actor)) {
    const suggestion = asciiSuggestion(actor)
    return {
      ok: false,
      message:
        'Your name can only use plain ASCII characters (A–Z, digits, spaces and punctuation), ' +
        'because it is recorded in the audit log of every approval.' +
        (suggestion ? ` Try "${suggestion}".` : ''),
    }
  }
  if (actor.length > ACTOR_MAX_LENGTH) {
    return {
      ok: false,
      message: `Your name is too long (${actor.length} characters, at most ${ACTOR_MAX_LENGTH}).`,
    }
  }
  if (isReservedActor(actor)) {
    return {
      ok: false,
      message:
        `"${actor}" is reserved: the killswitch records its own automatic steps under ` +
        `${RESERVED_ACTORS.map((n) => `"${n}"`).join(', ')} in the audit log, so an approval ` +
        'signed with it could not be told apart from one the controller made itself, and the ' +
        'killswitch refuses it. Sign in with your own name.',
    }
  }
  return { ok: true, actor }
}

// Letters that do not decompose into a base letter plus a combining mark.
const NO_DECOMPOSITION: Record<string, string> = {
  ł: 'l',
  Ł: 'L',
  đ: 'd',
  Đ: 'D',
  ø: 'o',
  Ø: 'O',
  æ: 'ae',
  Æ: 'AE',
  œ: 'oe',
  Œ: 'OE',
  ß: 'ss',
  þ: 'th',
  Þ: 'Th',
}

/** "Łukasz" → "Lukasz", "Michał" → "Michal"; empty when nothing sensible is left. */
function asciiSuggestion(name: string): string {
  const folded = [...name]
    .map((ch) => NO_DECOMPOSITION[ch] ?? ch)
    .join('')
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^\x20-\x7e]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, ACTOR_MAX_LENGTH)
  return folded && folded !== name ? folded : ''
}
