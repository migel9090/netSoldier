/**
 * One JSON object per line, shaped like the Go services' slog output
 * (time, level, msg, fields) so the same log pipeline can parse all of them.
 */

type Level = 'INFO' | 'WARN' | 'ERROR'

export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields })
  if (level === 'ERROR') console.error(line)
  else if (level === 'WARN') console.warn(line)
  else console.log(line)
}
