package drivers

import (
	"context"

	"github.com/migel9090/netSoldier/libs/events"
)

// Driver applies and reverts enforcement actions on the network.
// Each driver type (dns_sinkhole, arp_isolate, switch_acl) has its
// own implementation.
type Driver interface {
	Apply(ctx context.Context, action *events.EnforcementAction) error
	Revert(ctx context.Context, action *events.EnforcementAction) error
	Name() string
}
