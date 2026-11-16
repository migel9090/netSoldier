package drivers

import (
	"context"
	"errors"
	"fmt"

	"github.com/migel9090/netSoldier/libs/events"
)

// Driver applies and reverts enforcement actions on the network.
// Each driver type (dns_sinkhole, arp_isolate, switch_acl) has its
// own implementation.
//
// Apply and Revert must be idempotent: the controller retries both after a
// restart or an ambiguous failure. An error from Apply means "maybe
// applied" unless it wraps ErrNotApplied; an error from Revert means "still
// enforced". A driver whose backend confirms later returns ErrDeferred.
type Driver interface {
	Apply(ctx context.Context, action *events.EnforcementAction) error
	Revert(ctx context.Context, action *events.EnforcementAction) error
	Name() string
}

// ErrNotApplied marks an Apply failure that certainly changed nothing (the
// request was refused before anything was sent, or the backend said no).
// The controller then records apply_failed without a compensating revert.
var ErrNotApplied = errors.New("not applied")

// NotApplied wraps err as an Apply failure that changed nothing.
func NotApplied(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrNotApplied, err)
}

// ErrDeferred is returned by a driver that has submitted the change to a
// backend which confirms it later (the netagent). The action keeps its
// state until the confirmation, a refusal, or the deadline.
var ErrDeferred = errors.New("submitted; awaiting confirmation")

// Deferring is implemented by drivers that answer with ErrDeferred.
type Deferring interface {
	Deferred() bool
}

// Availability is implemented by drivers that can be configured and still
// unable to act at the moment (the netagent has not polled).
type Availability interface {
	Available() error
}

// IsDeferring reports whether d confirms its operations later.
func IsDeferring(d Driver) bool {
	df, ok := d.(Deferring)
	return ok && df.Deferred()
}
