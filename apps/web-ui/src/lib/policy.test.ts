import { describe, expect, it } from 'vitest'
import { normalisePolicy } from './api'
import {
  actionTypeRows,
  autoBlockSettingWords,
  policyRows,
  protectedRows,
  secondsWords,
} from './policy'
import type { Device } from './types'

// GET /policy as cmd/killswitch-controller/api.go handleGetPolicy writes it.
const POLICY = normalisePolicy({
  auto_min_confidence: 90,
  auto_min_severity: 'critical',
  auto_min_signals: 2,
  auto_require_known_bad: true,
  auto_action_type: 'dns_sinkhole',
  pend_min_confidence: 50,
  pend_min_severity: 'medium',
  default_ttl: 3600,
  default_action: 'dns_sinkhole',
  auto_block: 'off',
  auto_block_allowed: false,
  auto_block_disabled_reason: 'auto-block disabled: POLICY_AUTO_BLOCK=off',
  allowlist_entries: 2,
  rejected_protection_entries: 0,
  available_action_types: ['dns_sinkhole'],
  unavailable_action_types: {
    arp_isolate: 'NETAGENT_KILLSWITCH_TOKEN not set: no netagent can carry out an isolation',
    switch_acl: 'SWITCH_WEBHOOK_URL not set',
  },
  pending_ttl_seconds: 86400,
})

describe('policy rows', () => {
  it('puts every threshold and timing in words', () => {
    const rows = Object.fromEntries(policyRows(POLICY).map((r) => [r.key, r.value]))
    expect(rows).toEqual({
      pend_min: 'confidence ≥ 50, severity ≥ medium',
      auto_min: 'confidence ≥ 90, severity ≥ critical',
      auto_min_signals: '2 signal classes',
      auto_require_known_bad: 'yes',
      auto_action_type: 'DNS Sinkhole',
      default_action: 'DNS Sinkhole',
      default_ttl: '1 h',
      pending_ttl: '24 h',
    })
  })

  it('says "not reported" for what an older controller does not send', () => {
    const rows = policyRows(normalisePolicy({ available_action_types: ['dns_sinkhole'] }))
    expect(new Set(rows.map((r) => r.value))).toEqual(new Set(['not reported']))
  })

  it('writes durations the way people say them', () => {
    expect(secondsWords(90)).toBe('90 s')
    expect(secondsWords(600)).toBe('10 min')
    expect(secondsWords(86400)).toBe('24 h')
    expect(secondsWords(7 * 86400)).toBe('7 days')
    expect(secondsWords(0)).toBeNull()
    expect(secondsWords('3600')).toBeNull()
  })
})

describe('action types', () => {
  it('lists each known type with whether it can be chosen, and the controller’s reason when not', () => {
    expect(actionTypeRows(POLICY)).toEqual([
      { type: 'dns_sinkhole', name: 'DNS Sinkhole', available: true, reason: '', isDefault: true },
      {
        type: 'arp_isolate',
        name: 'ARP Isolation',
        available: false,
        reason: 'NETAGENT_KILLSWITCH_TOKEN not set: no netagent can carry out an isolation',
        isDefault: false,
      },
      {
        type: 'switch_acl',
        name: 'Switch ACL',
        available: false,
        reason: 'SWITCH_WEBHOOK_URL not set',
        isDefault: false,
      },
    ])
  })

  it('keeps a type the UI does not know, and does not invent a reason', () => {
    const rows = actionTypeRows(
      normalisePolicy({ available_action_types: ['router_acl'], unavailable_action_types: null }),
    )
    expect(rows.map((r) => [r.type, r.available, r.reason])).toEqual([
      ['dns_sinkhole', false, 'not reported by the controller'],
      ['arp_isolate', false, 'not reported by the controller'],
      ['switch_acl', false, 'not reported by the controller'],
      ['router_acl', true, ''],
    ])
  })

  it('ignores a malformed list of reasons', () => {
    const p = normalisePolicy({
      available_action_types: 'dns_sinkhole',
      unavailable_action_types: { arp_isolate: 5, switch_acl: 'no switch' },
    })
    expect(p.available_action_types).toEqual([])
    expect(p.unavailable_action_types).toEqual({ switch_acl: 'no switch' })
  })
})

describe('protected devices', () => {
  const devices = [
    { mac: 'AA:BB:CC:00:00:01', ip: '192.168.1.77', hostname: 'nas' },
    { mac: 'aa:bb:cc:00:00:02', ip: '192.168.1.10', hostname: 'host' },
  ] as Device[]

  it('names the entries the inventory knows, MACs first', () => {
    expect(
      protectedRows(
        { macs: ['aa:bb:cc:00:00:01'], ips: ['192.168.1.10', '10.0.0.0/8', '192.168.1.99'] },
        devices,
      ),
    ).toEqual([
      { kind: 'MAC', value: 'aa:bb:cc:00:00:01', name: 'nas' },
      { kind: 'IP', value: '192.168.1.10', name: 'host' },
      { kind: 'network', value: '10.0.0.0/8', name: '' },
      { kind: 'IP', value: '192.168.1.99', name: '' },
    ])
  })

  it('says how automatic blocking is configured', () => {
    expect(autoBlockSettingWords({ auto_block: 'off' })).toBe('off (POLICY_AUTO_BLOCK=off)')
    expect(autoBlockSettingWords({ auto_block: 'on' })).toBe('on (POLICY_AUTO_BLOCK=on)')
    expect(autoBlockSettingWords({})).toBeNull()
  })
})
