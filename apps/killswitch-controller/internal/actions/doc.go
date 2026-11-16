// Package actions is the killswitch's durable memory: every enforcement
// action, the rules and agent commands the drivers own, the evaluation
// ledger that makes POST /evaluate idempotent, and the audit log. It lives
// in one SQLite database (modernc.org/sqlite, pure Go), written with
// synchronous=FULL; every transition and its audit entry commit in one
// transaction, so neither is ever visible without the other.
//
// # States
//
//	state          meaning                                   moved by → to
//	-------------  ----------------------------------------  ---------------------------------------------
//	pending        waiting for a human                       operator → approved | rejected
//	                                                         policy (auto decision, same target) → approved
//	                                                         reaper (PendingTTL) → expired
//	                                                         capacity (MaxPending) → expired
//	approved       driver call outstanding; nothing          driver confirms → active
//	               confirmed yet                             driver refuses → apply_failed
//	                                                         unknown outcome, undone → apply_failed
//	                                                         unknown outcome, undo fails → revert_failed
//	active         enforced; expires_at = activated_at+TTL   operator / reaper (TTL) → reverted | revert_failed
//	                                                         reconciliation (gone for good) → reverted
//	revert_failed  STILL ENFORCED: a revert did not take     reaper retries with backoff → reverted
//	               effect (or an apply could not be undone)  (apply_failed if it never was active)
//	reverted, rejected, expired, apply_failed               terminal; only these are ever pruned
//
// Approve is a compare-and-swap (pending → approved): however many times it
// is sent, one caller wins and the driver runs once; the others get the
// action back. Nothing ever reports revert_failed as reverted: only a
// driver's confirmation, or reconciliation seeing the enforcement gone,
// ends it.
//
// # Actors
//
// Every transition records who caused it. Operators are named by the
// X-Netsoldier-Actor header of an operator-authenticated request (identity
// fields in bodies are ignored). The controller's own actors are reserved:
// auto-policy (creations, automatic approvals), ttl (the reaper),
// reconcile (reconciliation), netagent (a result the agent reported) and
// system (capacity eviction).
//
// Each entry names who did what that entry records, so the trail of an
// isolation reads "approved: alice, active: netagent" — alice asked, the
// agent confirmed, possibly much later:
//
//   - An approval names who approved (operator or auto-policy).
//   - An apply's outcome (active, apply_failed) names who settled it. For a
//     deferred driver that is the netagent: its confirmation, its refusal,
//     or its silence past the deadline. A synchronous driver answers inside
//     the call made for whoever asked, and there is no other party to name:
//     the outcome carries the asker, the reason names the driver.
//   - A revert's outcome (reverted, revert_failed) names who asked for the
//     outstanding revert (operator, ttl), whoever confirmed it. Starting a
//     revert writes no entry, so this is the only one that can say who
//     lifted the enforcement — and reverted_by is taken from it. An
//     enforcement that ends with no revert outstanding names who ended it,
//     or found it ended (netagent, reconcile, ttl).
//
// # Outstanding operations
//
// Before a driver is called the store records the operation (Op), who asked
// for it and its deadline. A synchronous call that a restart interrupted
// therefore has a defined outcome: an apply is undone, a revert retried. A
// deferred operation (the netagent confirms later) keeps its deadline across
// the restart; the agent's result or the deadline decides. The API serves
// the outstanding operation as the action's in_flight (apply, revert): a
// revert under way does not change the state until it is confirmed.
//
// # What the reaper owns
//
// Pending actions past their deadline (→ expired), active actions past
// expires_at (revert), revert_failed actions whose backoff has run out
// (retry), operations past their deadline (no confirmation → apply_failed,
// or revert_failed with a retry scheduled), and pruning: finished actions
// beyond MaxTerminal, old evaluations, forwarded audit entries past their
// retention, finished agent commands.
//
// # Reconciliation
//
// At start-up and periodically the sinkhole compares its rule claims with
// AdGuard: a rule it added that nothing needs is removed; a rule it did not
// add is never touched; an enforcement that is missing is recorded as ended
// (actor reconcile) and not silently re-created, since it was most likely
// removed by hand; if AdGuard cannot be read nothing changes. On every poll
// the netagent's active list is compared with the isolations in force: one
// nobody owns is released, a wanted one the agent dropped is issued again
// for the rest of its TTL (the agent extends rather than duplicates), and a
// revert_failed one the agent no longer has did end after all. Findings
// are logged and counted in killswitch_reconcile_findings_total.
//
// # Deduplication and bounds
//
// One detection id is one action. A detection for a client and target that
// already have an open action (pending, approved, active, revert_failed)
// folds into it; an automatic decision promotes a pending one instead of
// creating a second. The approval queue holds MaxPending actions; a new
// one beyond that expires the oldest.
//
// # Audit outbox
//
// The local audit log is the record. When ClickHouse is configured, a
// Forwarder sends entries in order and marks them forwarded only once
// accepted, retrying with backoff for as long as it takes; GET /audit serves
// the local log.
package actions
