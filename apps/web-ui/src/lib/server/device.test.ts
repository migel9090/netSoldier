import { describe, expect, it } from 'vitest'
import { DEVICE_TTL_SECONDS, issueDeviceToken, verifyDeviceToken } from './device'

const SECRET = 'device-test-secret-device-test-secret'

describe('device tokens', () => {
  it('round-trips a device id and keeps a given one', () => {
    const { token, deviceId } = issueDeviceToken(SECRET)
    expect(verifyDeviceToken(SECRET, token)).toBe(deviceId)
    expect(verifyDeviceToken(SECRET, issueDeviceToken(SECRET, deviceId).token)).toBe(deviceId)
  })

  it('expires after its TTL', () => {
    const now = Date.now()
    const { token } = issueDeviceToken(SECRET, undefined, now)
    expect(verifyDeviceToken(SECRET, token, now + (DEVICE_TTL_SECONDS - 1) * 1000)).not.toBeNull()
    expect(verifyDeviceToken(SECRET, token, now + DEVICE_TTL_SECONDS * 1000)).toBeNull()
  })

  it('uses a key derived from SESSION_SECRET, not the secret itself', () => {
    const { token } = issueDeviceToken(SECRET)
    expect(verifyDeviceToken('another-secret-another-secret-0000', token)).toBeNull()
  })

  it('treats anything else as no cookie, without throwing', () => {
    const { token } = issueDeviceToken(SECRET)
    const [, id, exp, sig] = token.split('.')
    const inputs: unknown[] = [
      undefined,
      '',
      'garbage',
      `v1.${id}.${exp}`,
      `v1.${id}.${exp}.${sig}.extra`,
      `v2.${id}.${exp}.${sig}`,
      `v1.${id}.${Number(exp) + 1}.${sig}`,
      `v1.short.${exp}.${sig}`,
      `v1.${id}.-1.${sig}`,
      'x'.repeat(10_000),
      42,
      null,
    ]
    for (const input of inputs) {
      expect(verifyDeviceToken(SECRET, input as string | undefined), String(input)).toBeNull()
    }
  })
})
