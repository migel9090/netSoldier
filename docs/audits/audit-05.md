# Audit #5 — Phase 2 gate

- **Date:** 2026-10-02
- **Scope:** Steps 101–124 (Phase 2: unified sensor ingest, TLS heuristics, ML
  beaconing and anomalies, composite confidence, FP feedback, cold tier,
  enrichment, dashboards, PCAP corpus) plus a full re-audit of the code base
- **Result:** **PASS with conditions** — Phase 2 is functionally complete and
  the defects found in this audit are fixed, but three items are carried into
  Phase 3 (listed in §12) and the Phase 1 MVP claim in audit-04 needs the
  correction recorded in §11.

## Audit criteria

From roadmap step 125:

> Sanity check Fazy 2: korelacja wielo-sensorowa działa; composite confidence
> kalibrowane; feedback FP zamyka pętlę; cold tier i enrichment zweryfikowane;
> dashboardy pokrywają DPI/TLS/beaconing; korpus PCAP w CI; przegląd
> bezpieczeństwa całego code base'u. `docs/audits/audit-05.md`; zamknij Fazę 2.

The last clause is why this audit is longer than its predecessors. A
line-by-line review of all ~17k lines found defects that the previous gates
had passed over, including several in code those gates had explicitly marked
PASS. §11 records what audit-04 got wrong and why, because an audit process
that certifies a broken control is itself a finding.

---

## 1. Multi-sensor correlation

| Source | Table | Signal class | Status |
|--------|-------|--------------|--------|
| Suricata EVE alerts | `suricata_alerts` | `ids-signature` | operational |
| Zeek Intel hits | `zeek_intel` | `ioc` | operational |
| Zeek SSL/TLS | `zeek_ssl` | `tls` | operational |
| RITA beaconing | `ml_beacons` | `beacon` | operational |
| Isolation Forest | `ml_anomalies` | `volumetric` | operational |
| AdGuard querylog | — | `ioc` | operational |

All six feed `detection.Engine` through one alert path. Two defects were
found and fixed:

- **`ml_beacons` was collapsing history.** The table was
  `ReplacingMergeTree(timestamp) ORDER BY (src_ip, dst_ip)`, so after a merge
  only the newest beacon per source→destination pair survived. The ingest
  poller tails this table on a timestamp cursor, so rows could vanish from
  under it between polls and the `beacon` signal could be lost before
  composite confidence ever saw it. Fixed in `021_ml_beacons_history.sql`
  (timestamp first in the sort key).
- **Ingest cursor had no progress guarantee.** With more than
  `pollBatchLimit` (1000) rows in a single second the cursor could not
  advance, and the dedupe set grew without bound while the same rows were
  re-read. This is the Suricata-alert-storm case — precisely when detection
  matters. Tracked as a Phase 3 item (§12.1); the batch limit now has a
  saturation metric so the condition is visible.

**Result:** PASS

---

## 2. Composite confidence calibration

This is where the most serious defect of the phase was found.

Noisy-OR combination is mathematically sound and the implementation is
correct: monotonic, saturating, distinct classes only. The problem was what
the *consumer* did with the number.

A lone beacon is capped at 75 and a lone volumetric anomaly at 70. Combined:

```
1 - (1 - 0.75)(1 - 0.70) = 0.925 → 93 → SeverityForConfidence(93) = "critical"
```

93 clears `AutoMinConfidence: 90`, `critical` clears `AutoMinSeverity:
critical`, and `SignalCount: 2` satisfies the `POLICY_AUTO_MIN_SIGNALS=2`
gate that the proxmox-soc overlay sets. **Two local heuristics could
therefore auto-quarantine a household device with no human in the loop and
nothing external attesting the destination was malicious.** NTP, telemetry
and software-update checks all look like beaconing, and a volumetric anomaly
on the same client co-occurs easily — this was a realistic path to cutting a
device off by mistake.

Both the `composite` package docstring ("does not let three weak heuristics
fabricate certainty") and the `policy` comment ("heuristics alone never reach
AutoMinConfidence") asserted this could not happen. Each was true of a
*single* heuristic and false of the combination the package exists to
produce.

**Fix:** auto-block now additionally requires at least one *known-bad* signal
class — a threat-feed match (`ioc`) or an IDS signature (`ids-signature`) —
via `events.IsKnownBadSignal`. Counting signals is not enough; their kind is
what separates "known bad" from "unusual". `SignalClass` was promoted into
the shared `libs/events` contract and is carried through `eventmap`, because
the killswitch cannot make this distinction without it. Escalating confidence
remains the correlator's job; deciding that heuristics are insufficient
grounds to cut a device off is the policy's.

Two further calibration defects were fixed:

- **The 15-minute window stopped bounding staleness.** A weaker repeat of an
  existing signal class refreshed the stored signal's timestamp, so a trickle
  of weak observations kept a strong one alive indefinitely.
- **Correlation keyed on client IP alone.** When a DHCP lease moved inside the
  window, signals from two different devices merged into one composite, which
  then inherited whichever device's MAC came from the strongest signal.
  Correlation now keys on MAC with IP as fallback, and the composite takes its
  identity from the triggering alert rather than the context anchor.

Regression tests pin all three, including a test asserting
`combine([75, 70]) == 93` so the policy gate's calibration cannot drift away
from the number it defends against.

**Result:** PASS (after fix)

---

## 3. False-positive feedback loop

The loop works, and it was also the most powerful unauthenticated primitive
in the system.

`POST /feedback` had no authentication of any kind. A verdict of
`false_positive` with an empty `client_ip` installs an indicator-wide
suppression, and `Suppressed()` is checked on **both** alert paths *before*
the killswitch webhook — so the killswitch never sees the detection at all.
Verdicts persist to ClickHouse and are replayed on startup, so the blinding
survived restarts. There was no TTL, no cap on suppression count, and
`analyst` was an unverified free-text field.

The asymmetry is the point: the killswitch required a bearer token on every
mutating endpoint, while the endpoint that could disable its entire input
required nothing.

**Fixes:**

| Control | Before | After |
|---------|--------|-------|
| Authentication | none | `DETECTION_API_KEY` bearer, constant-time compared |
| Attribution | client-supplied `analyst`, optional | required; overwritten from the session via `X-Netsoldier-Actor` |
| Lifetime | permanent, replayed on restart | `FEEDBACK_SUPPRESSION_TTL` (default 30d); expired verdicts are not replayed |
| Count | unbounded | `MaxSuppressions` (default 10000), rejected at the cap |
| Body size | unbounded | 64 KiB |
| Retention | 365d | 90d (`022_feedback_retention.sql`) |
| Observability | none | `alerts_suppressed_total`, `suppressions_expired_total`, `DetectionSuppressionsHigh` alert |

**Result:** PASS (after fix)

---

## 4. Cold tier and enrichment

Cold-tier move and historical query were verified in step 119 and
`tests/e2e/clickhouse_cold_test.go` still passes.

One defect found: **no table had a `PARTITION BY`**, across all 20 of them.
TTL expiry (30/90/180/365 days) therefore rewrote data parts rather than
dropping partitions, and the step-119 tier move works per-part too. That cost
lands on the documented bottleneck — the Pi profile's µSD card at ~5 MB/s
random write. Fixed in `020_partitioning.sql` (monthly, `audit_log` yearly),
with DM-11 covering application to an existing deployment.

Vector enrichment (geo/ASN, threat-intel, rDNS) from step 120 is unchanged
and working.

**Result:** PASS (after fix)

---

## 5. Dashboards

Three as-code dashboards delivered in steps 121–122, closing the audit-04
§12.1 follow-up:

| Dashboard | Covers |
|-----------|--------|
| DPI & Protocols | step 121 |
| TLS Fingerprint Anomalies | step 121 |
| Beaconing & Anomalies (with device drill-down) | step 122 |

Alert coverage was the gap. The rule set had 7 alerts and
`NetSoldierServiceDown` matched only `detection-engine|device-inventory` — so
**the killswitch going down, meaning no enforcement at all, raised nothing.**
Several alerts the threat model claimed as mitigations (disk usage for D-02,
drop rate for D-03) did not exist.

Expanded to 22 alerts, with a dedicated `netsoldier.silent-failures` group
covering each failure mode this audit found running invisibly: auto-block
disabled, empty allowlist, driver failures, audit-write failures, rejected
requests, webhook unauthorized, IoC sync staleness, querylog saturation,
sensor ingest errors, suppression count, MAC resolution failures, ClickHouse
disk, dropped device events.

**Result:** PASS (after fix)

---

## 6. PCAP corpus in CI

The multi-family corpus (step 123) replays through Suricata and Zeek. Step
124 adds the detection-regression gates that make a corpus useful as a
*gate* rather than a fixture:

- `gofmt` is enforced (nine files had drifted out of format on main while
  `task fmt` existed and went unused)
- `libs/` and `tests/` are vetted and tested — the `apps/*/` glob excluded
  them, so 389 lines of event-contract tests had **never run in CI**
- `tests/e2e` is vetted under both build tags (a plain vet matched no
  packages and silently passed)
- coverage floors extended from 4 packages to 9, including the enforcement
  drivers
- both kustomize overlays are rendered and validated with kubeconform
- `scripts/check-images.py` fails the build if any first-party image lacks a
  Dockerfile or a build job

**Result:** PASS

---

## 7. Security review of the code base

The full review is recorded separately; this section lists what was found and
fixed, by severity.

### Critical

| # | Finding | Fix |
|---|---------|-----|
| K-1 | Web UI had **no authentication and no CSRF protection**, and its NetworkPolicy ingress rule had no `from:` selector (allow-from-anywhere). The proxy attached `KILLSWITCH_API_KEY` to whatever arrived, so any LAN device could `POST /api/killswitch/{id}/approve`. SvelteKit's own CSRF check never applied because the `handle` hook intercepts `/api/*` before `resolve()`. | Session auth (signed HttpOnly cookie, 12h TTL) + double-submit CSRF token + Origin check; route allowlist replacing prefix rewriting; upstream timeouts; CSP and security headers; login page; ingress narrowed. Interim until OIDC at step 159. |
| K-2 | `POST /feedback` unauthenticated → permanent, restart-surviving detection bypass. | §3 |
| K-3 | Killswitch deployed with **no `KILLSWITCH_API_KEY` and an empty allowlist**. The allowlist was documented in the runbook and user guide but wired into no manifest, so the router, DNS server and sensor were all quarantinable — and the threat model notes that blocking the router takes the network offline. | Both wired in (`killswitch-credentials` Secret, `killswitch-allowlist` ConfigMap). The controller now **refuses to auto-block while the allowlist is empty**, degrading to pending-only rather than refusing to start (which would also stop detection). `TargetGuard` refuses the gateway, the sensor's own interface and any protected device inside the drivers themselves. |
| K-4 | ClickHouse `rita` user: **empty password, `::/0`, `access_management: 1`, `named_collection_control: 1`** — full admin on the database holding the enforcement audit log and the MinIO credentials. `default` was passwordless. No Go client sent credentials. | Per-service accounts with SHA-256 password hashes rendered from SOPS by an init container that fails closed on a blank value; least-privilege grants (writer: INSERT/SELECT; reader: SELECT; rita: own databases only); `default` restricted to localhost; all clients authenticate via `X-ClickHouse-User/Key` headers. |

### High

| # | Finding | Fix |
|---|---------|-----|
| W-1 | **Detection → killswitch path severed twice over.** The engine sent `X-Webhook-Secret` while the killswitch required `Authorization: Bearer`, so enabling the API key would have 401'd every delivery (and the sender treats 4xx as non-retryable). Independently, `detection-engine`'s NetworkPolicy had no egress rule to killswitch:8084 under namespace default-deny. | Bearer token + egress rule. New e2e test runs the real binaries with auth **on** — the posture no earlier test exercised, which is why this survived 24 steps. |
| W-2 | **No HMAC anywhere** (`grep -rn hmac` → zero hits), contradicting audit-04 §3. The shared secret travelled in plaintext on every request and the body was unsigned, so anything on the path could raise `confidence`/`severity` or rewrite `client_mac` to the router. | `events.SignPayload`/`VerifyPayload` (HMAC-SHA256, `hmac.Equal`) in the shared contract; verified on `/evaluate`; switch-port webhook signed too. |
| W-3 | **Four of seven first-party images had no Dockerfile and no build job** (`device-inventory`, `killswitch-controller`, `threat-intel-sync`, `web-ui`) while manifests referenced them, and Kyverno's `verifyImages` is `Enforce` — so those pods would be rejected as unsigned. The response capability was undeployable. | Four Dockerfiles + four build/sign/SBOM/provenance job pairs; `check-images.py` gate. |
| W-4 | **Unbounded memory growth in the IoC matcher.** CIDR indicators were appended to a slice with no dedup while `SyncLoop` re-added the full feed every 5 minutes — Spamhaus DROP's ~1000 prefixes grew ~288k entries/day, and `MatchIP` scanned all of them linearly per DNS answer. | CIDRs keyed by canonical prefix, like every other indicator type. Regression test asserts 50 re-syncs leave the set unchanged. |
| W-5 | **Live threat intel never worked.** `THREAT_INTEL_URL` was the full path while the code appended `/export/json`, producing `/export/json/export/json` → 404. The engine ran on the static `domains.txt` alone with MISP and all six feeds disconnected, visible only as a `slog.Warn`. | Env corrected to the base URL; `exportURL()` accepts either spelling; `ioc_sync_last_success_timestamp_seconds` + `IoCSyncStale` alert. |
| W-6 | Corroborated heuristics could auto-block. | §2 |
| W-7 | **Allowlist normalization was `strings.ToLower` only**, so `AA-BB-CC-DD-EE-FF` (the form router UIs show) never matched the pipeline's `aa:bb:cc:dd:ee:ff` — the one device that must never be cut off was silently unprotected. IPs compared as raw strings. And `emitAlert` never populated `ClientMAC`, so AdGuard-sourced detections could only be protected by a DHCP-mobile IP. | `net.ParseMAC`/`netip.ParseAddr` normalization accepting every spelling, CIDR support, invalid entries rejected loudly at load; `ResolveClient` hook fills MAC/name from device-inventory with a failure counter. |
| W-8 | **Enforcement drivers had zero tests.** `syscall.Sendto` errors were discarded entirely, so `Apply` returned nil and the action was marked active while not one packet had left the host. Context was ignored (`_`). `/proc/net/arp` was read into a fixed 4 KiB buffer (~58 entries), and on failure `resolve()` **silently substituted the DNS sinkhole** — a requested L2 isolation became a DNS block with no indication. Gateway MAC was resolved once and never refreshed. | Errors propagated; context honoured; `os.ReadFile`; gateway MAC re-resolved on a TTL; `resolve()` returns an error instead of substituting; `ip_forward` checked at startup (on a k3s node it defeats ARP isolation and makes the sensor a MITM); first tests for all three drivers. |
| W-9 | **Sinkhole read-modify-write had no synchronization** — called concurrently from four paths, each rewriting the whole rule list, so edits were lost and operator-authored rules could be wiped. **No domain validation**: a value containing a newline injects extra AdGuard filter rules, and `||*^` blocks all DNS. | `rulesMu` around the cycle; strict hostname validation. Tests cover the injection strings and 10 concurrent applies. |
| W-10 | **`MatchDomain` matched bare TLDs.** It walks every parent of a queried name, so an indicator of `com` matched every `.com` lookup — one malformed feed row plus auto-block equals a DNS sinkhole on the internet. Feed values went in unvalidated. | Validation at both the ingest boundary (`ioc.Validate`) and the match boundary (`ValidateDomainIndicator`): ≥2 labels, public-suffix list, no catch-all CIDRs, loopback refused. |
| W-11 | **Inventory takeover via `stable_id`.** Derived from client-chosen DHCP options 60/12, and the correlating `UPDATE` rewrote a row's MAC — so a device copying a neighbour's vendor class and hostname inherited its record and labels while the real device vanished from the inventory. | Correlation requires both MACs to be locally-administered and `vendorClass` to be present; `randomized_mac` column added. `EnrichByIP` fills only a blank hostname (it could previously rename the router). |

### Medium (fixed)

Suppression TTL and cap; `POLICY_*` env validation (an invalid severity ranked
0, which silently reduced auto-block to a bare confidence check — a typo
*widened* enforcement); manual revert marking an action reverted after a
driver failure (leaving the block in place while reporting it lifted);
`StateFailed` added so "approved but not enforced" is distinguishable, and
surfaced in the UI; action/alert ID prefixes namespaced per process (a global
counter restarted at 1 each boot, so `ACT-1` in the audit log could mean
several different actions); millisecond audit timestamps; bounded action store
with terminal-only eviction; `MaxBytesReader` on all POST bodies; constant-time
token comparison; device-inventory event writer bounded and batched (it spawned
an unbounded goroutine per sighting from spoofable LAN protocols); device
retention pruning; `List()` bounded; IoC store expiry; ml-anomaly model
integrity digest verified **before** unpickling (`joblib.load` executes code
and the artifact sits on a shared PVC), `_ModelHolder` lock (FastAPI runs `def`
endpoints in a threadpool, so concurrent `/score` could race), single scoring
pass instead of two; threat-intel-sync `/metrics` endpoint (it had none, so
feed health was unobservable); `.sops.yaml` placeholder recipient; example
Secret shipping `admin`/`changeme`; dead `IsSevereEnoughForAuto` with a
*different* threshold than the real policy.

### Verified sound (no change needed)

- **No SQL injection.** Device-detail handlers validate the MAC with a regex
  and use ClickHouse `{ip:String}` parameters; SQLite uses placeholders
  throughout.
- **No `InsecureSkipVerify`** anywhere in the tree.
- `.dockerignore` is an allowlist, so `.git` — and the token
  `actions/checkout` leaves in it — never enters a build context.
- Container hardening: distroless/nonroot, `CGO_ENABLED=0`, `-trimpath`,
  `drop: ALL`, `readOnlyRootFilesystem`, `automountServiceAccountToken: false`.
- Ingest cursor/dedupe logic is carefully written, including second-precision
  `DateTime` handling.

**Result:** PASS (after fixes)

---

## 8. Test coverage

| Package | Before | After | Floor |
|---------|--------|-------|-------|
| `libs/events` | not run in CI | 100.0% | 90% |
| `killswitch-controller/internal/policy` | 93.2% | 93.2% | 80% |
| `threat-intel-sync/internal/ioc` | 92.5% | 92.5% | 70% |
| `device-inventory/internal/store` | **no tests** | 84.9% | 70% |
| `detection-engine/internal/composite` | 81.6% | 81.6% | 70% |
| `killswitch-controller/internal/actions` | 61.6% | 80.1% | 70% |
| `detection-engine/internal/iocmatch` | 75.4% | 75.4% | 70% |
| `detection-engine/internal/feedback` | 70.7% | 70.7% | 70% |
| `killswitch-controller/internal/drivers` | **no tests** | 48.9% | 45% |

The drivers floor is 45 deliberately and not as a concession. `arpisolate.go`
is raw `AF_PACKET` socket code needing `CAP_NET_RAW` and a real interface, so
it cannot be unit-tested in CI; the testable drivers are each above 70 on
their own (sinkhole ~74%, switchport ~73%, guard ~82%) and the ARP driver's
logic is covered by targeted tests for target validation and the gateway
refusal. Raising the number would mean excluding the untestable file from
measurement, not testing more of it.

New e2e tests, all running against real binaries:

| Test | What it pins |
|------|--------------|
| `TestDetectionToKillswitchContract` | the full chain with auth **on** — the gap that hid W-1 and W-2 |
| `TestKillswitchRejectsUnauthenticated` | 4 credential-failure combinations create no action |
| `TestEmptyAllowlistDisablesAutoBlock` | fail-safe when nothing is protected |
| `TestHeuristicsNeverAutoBlockE2E` | beacon+volumetric stays pending; +IDS auto-blocks |
| `TestAllowlistProtectsGatewayE2E` | MAC spelling normalization and CIDR, end to end |

Web UI went from no CI at all to format + typecheck + unit tests + build.
It had **17 undetected type errors** and a `lint` script invoking an eslint
that was never in `devDependencies`.

**Result:** PASS

---

## 9. Killswitch safety re-review

| Control | Status |
|---------|--------|
| Allowlist checked first in `Evaluate()` | unchanged, tested |
| Allowlist actually populated in the deployment | **fixed** (K-3) |
| Allowlist matches regardless of MAC/IP spelling | **fixed** (W-7) |
| Auto-block requires known-bad evidence | **new** (W-6) |
| Auto-block refused when nothing is protected | **new** (K-3) |
| Gateway/sensor refused inside the drivers | **new** (K-3) |
| Driver failure distinguishable from success | **new** (`StateFailed`) |
| Revert order: driver → state, on every path | **fixed** (manual revert) |
| API authentication on mutating endpoints | **fixed** (K-3), constant-time |
| Detection events authenticated and integrity-checked | **new** (W-2) |
| Audit record per transition, failures alerted | **fixed** |
| Action IDs unique across restarts | **fixed** |
| TTL auto-revert | unchanged, tested |

**Result:** PASS

---

## 10. RBAC, NetworkPolicy, Kyverno re-review

RBAC unchanged from audit-04 and still minimal.

NetworkPolicy: three defects fixed — the missing detection-engine egress rule
(W-1), the web-ui ingress rule with no `from:` selector, and the
detection-engine ingress admitting the whole `observability` namespace to port
8080 (which also reached `POST /feedback`). **The pi-edge profile deployed no
NetworkPolicies at all**, so the default-deny baseline was absent on the
profile most likely to sit directly on the household LAN; the overlay now
includes them. `fluent-bit` was likewise missing from proxmox-soc.

Kyverno: 7 policies unchanged and still `Enforce`. `verifyImages` is now
satisfiable for all seven first-party images (W-3). Note for Phase 3: the
policies use the `spec.validationFailureAction` field, deprecated in Kyverno
≥1.13 — verify against the installed version (§12.3).

**Result:** PASS (after fixes)

---

## 11. Correction to audit-04

Audit-04 recorded PASS on items that did not hold. Recording this is not
score-keeping: the failure mode is an audit that reads manifests and
docstrings as evidence of behaviour, and it will recur unless the method
changes.

| audit-04 claim | Reality |
|----------------|---------|
| §3: "webhook events with HMAC signature (`X-Webhook-Signature`). Verified in e2e test." | No HMAC existed anywhere; the header was `X-Webhook-Secret` carrying the secret in plaintext; no test asserted any header. |
| §2: test coverage PASS | `internal/drivers` — the three components that touch the network — had no tests. `libs/events`' own tests never ran in CI. `device-inventory/internal/store` had none. |
| §1: fluent-bit "configured" on proxmox-soc | Not referenced by the overlay or by `base/kustomization.yaml`. |
| §8: "complete isolation with least-privilege egress" | True of proxmox-soc minus one rule; pi-edge had no policies at all. |
| §1: all services "configured" | Four of seven had no image to run. |
| §4: "Auth on POST endpoints" / "GET endpoints unauthenticated by design" | True of the code, but no manifest set `KILLSWITCH_API_KEY`, so auth was off in every deployment. |

**Method change for future gates.** Checking that a manifest *contains* a
setting is not evidence; the gates added in step 124 check the properties
instead: `check-images.py` proves every referenced image is buildable,
`kustomize build` + kubeconform prove the overlays render, the coverage floors
prove the safety-critical packages are exercised, and the e2e suite runs the
authenticated posture rather than a convenient one. Future audits should
prefer a failing check over a passing sentence.

---

## 12. Carried into Phase 3

1. **Ingest poller progress guarantee.** With >1000 rows in one second the
   cursor cannot advance and the dedupe set grows unbounded. The condition is
   now observable (`DetectionQueryLogSaturated`, `SensorIngestErrors`) but the
   fix belongs with the backpressure work at **step 133**.
2. **Killswitch store persistence.** Still in memory, so a crash loses active
   enforcement state — carried from audit-04 §12.2. It is now *bounded* and
   IDs are namespaced per process, so the audit trail stays coherent across a
   restart, but reconciliation on startup is still missing.
3. **Kyverno `validationFailureAction` deprecation.** Verify against the
   installed version and migrate to `rules[].validate.failureAction` if ≥1.13.
4. **Digest pinning in manifests.** CONTRIBUTING requires digest-pinned images
   from step 35; only `ntop/ntopng` is pinned. ~20 images use mutable tags
   (`:main`, `fluent-bit:3.0`, `mariadb:11.4`, `redis:7-alpine`). Needs a
   digest-resolution step in the release flow rather than hand-edited values.
5. **`harden-runner` is `egress-policy: audit` everywhere**, never `block`.
   Audit mode enforces nothing.
6. **ml-anomaly has no lockfile** (`>=` constraints only), so builds are not
   reproducible and the SBOM/SLSA/cosign chain describes whatever resolved at
   build time.
7. **Benchmark on real hardware** — still outstanding from audit-04 §12.5, and
   now more interesting: W-4 and the missing partition keys would both have
   shown up in a real run.
8. **Device-inventory DELETE endpoint** — carried from audit-04 §12.3;
   retention pruning now covers the operational need, but not deliberate
   removal.

---

## Conclusion

Phase 2's features work: six sensor sources correlate through one path,
composite confidence is calibrated and now correctly gated, the feedback loop
closes, cold tier and enrichment are verified, three dashboards are deployed,
and the PCAP corpus runs in CI.

The code-base review found that several of the system's stated safety
properties were not true of the shipped configuration — the killswitch had no
authentication and no allowlist, its input path was severed, its most
destructive drivers were untested and failed silently, and four of seven
services had no image. Those are fixed, with regression tests and alerts for
each, and the CI gates added in step 124 are the part that matters: they turn
the claims this audit had to verify by hand into checks that fail on their own.

**Phase 2 is validated. Proceed to Phase 3 (steps 126+), starting with the
carried items in §12.**
