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
// system (capacity eviction). An activation or failure carries the actor
// who asked for the operation.
//
// # Outstanding operations
//
// Before a driver is called the store records the operation (Op), who asked
// for it and its deadline. A synchronous call that a restart interrupted
// therefore has a defined outcome: an apply is undone, a revert retried. A
// deferred operation (the netagent confirms later) keeps its deadline across
// the restart; the agent's result or the deadline decides.
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
