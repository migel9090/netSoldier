package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// insecureEnv lets the service start with authentication incomplete. It is
// for a lab bench only, and everything it relaxes is logged at error level.
const insecureEnv = "KILLSWITCH_ALLOW_UNAUTHENTICATED"

// credentials are the two bearer tokens the API accepts.
//
// They are separate because the detection-engine parses untrusted network
// data and is the component most likely to be compromised. With one shared
// key it could approve, reject or revert the very actions it submitted; with
// the ingest token it can only submit, and only signed events.
//
// The netagent has a third, because its results move actions: it can only
// poll, and nothing else can.
type credentials struct {
	operator string // KILLSWITCH_API_KEY: every endpoint except POST /evaluate and the agent's
	ingest   string // KILLSWITCH_INGEST_TOKEN: POST /evaluate, with the signature
	agent    string // NETAGENT_KILLSWITCH_TOKEN: POST /agent/v1/poll; optional
}

// loadAuth reads the credentials and the webhook signature secret. A missing
// token used to switch its check off with a log line; now any gap refuses
// the start, unless KILLSWITCH_ALLOW_UNAUTHENTICATED=true. The agent token
// is optional — without it there is no ARP isolation — but when it is set
// it must be a credential of its own.
func loadAuth(tolerance time.Duration) (credentials, *events.SignatureVerifier, error) {
	creds := credentials{
		operator: os.Getenv("KILLSWITCH_API_KEY"),
		ingest:   os.Getenv("KILLSWITCH_INGEST_TOKEN"),
		agent:    os.Getenv("NETAGENT_KILLSWITCH_TOKEN"),
	}
	secret := os.Getenv("WEBHOOK_SECRET")

	if creds.agent != "" && (creds.agent == creds.operator || creds.agent == creds.ingest) {
		// Not waivable: with a shared token the agent could approve, or
		// the web UI could report isolations lifted.
		return credentials{}, nil, fmt.Errorf("NETAGENT_KILLSWITCH_TOKEN must differ from " +
			"KILLSWITCH_API_KEY and KILLSWITCH_INGEST_TOKEN")
	}

	var problems []string
	if creds.operator == "" {
		problems = append(problems, "KILLSWITCH_API_KEY (operator token) is not set: approve, reject, "+
			"revert and the action lists would be open to anyone who can reach the service")
	}
	if creds.ingest == "" {
		problems = append(problems, "KILLSWITCH_INGEST_TOKEN (ingest token) is not set: anyone who can "+
			"reach the service could submit detection events")
	}
	if creds.operator != "" && creds.operator == creds.ingest {
		problems = append(problems, "KILLSWITCH_API_KEY and KILLSWITCH_INGEST_TOKEN are the same value: "+
			"the detection-engine could approve its own actions")
	}
	if secret == "" {
		problems = append(problems, "WEBHOOK_SECRET is not set: detection events could not be verified "+
			"and their contents could not be trusted")
	}

	var verifier *events.SignatureVerifier
	if secret != "" {
		verifier = &events.SignatureVerifier{Secret: secret, Tolerance: tolerance}
	}
	if len(problems) == 0 {
		return creds, verifier, nil
	}
	if !envBool(insecureEnv) {
		return credentials{}, nil, fmt.Errorf("%s; set %s=true to run like this anyway (lab only)",
			strings.Join(problems, "; "), insecureEnv)
	}
	for _, p := range problems {
		slog.Error("INSECURE: "+p, "override", insecureEnv)
	}
	return creds, verifier, nil
}

// protectInfrastructure adds the devices the controller protects on its own
// account to the policy: every address and MAC of the sensor's own
// interfaces, and the DNS server it enforces through. (The gateway comes
// from GATEWAY_IP / GATEWAY_MAC, loaded with the policy.)
//
// It returns an error when one of them could not be determined. The caller
// then withholds the device-level drivers: a driver that can cut a device
// off must not run while the guard does not know what to protect.
func protectInfrastructure(ctx context.Context, pol *policy.Policy, adguardURL string,
	lookup func(context.Context, string) ([]netip.Addr, error)) error {
	var errs []error

	ifaces, err := net.Interfaces()
	if err != nil {
		errs = append(errs, fmt.Errorf("list the sensor's own interfaces: %w", err))
	}
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 6 && !allZero(iface.HardwareAddr) {
			if err := pol.Infrastructure.AddMAC(iface.HardwareAddr.String()); err != nil {
				errs = append(errs, err)
			}
		}
		addrs, err := iface.Addrs()
		if err != nil {
			errs = append(errs, fmt.Errorf("addresses of %s: %w", iface.Name, err))
			continue
		}
		for _, a := range addrs {
			// Only the host address: protecting the interface's whole subnet
			// would protect every device on the LAN.
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				if err := pol.Infrastructure.AddIP(addr.Unmap().String()); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	dns, err := dnsServerAddrs(ctx, adguardURL, lookup)
	if err != nil {
		errs = append(errs, fmt.Errorf("DNS server address: %w", err))
	}
	for _, addr := range dns {
		if err := pol.Infrastructure.AddIP(addr.String()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// dnsServerAddrs resolves the host of the AdGuard URL the sinkhole driver
// talks to.
func dnsServerAddrs(ctx context.Context, adguardURL string,
	lookup func(context.Context, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	u, err := url.Parse(adguardURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("ADGUARD_URL %q has no host", adguardURL)
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := lookup(lctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return out, nil
}

func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// buildGuard gives the drivers every protected device: the operator's
// allowlist and the infrastructure.
func buildGuard(pol *policy.Policy) (*drivers.TargetGuard, error) {
	var g drivers.TargetGuard
	for _, set := range []*policy.Allowlist{&pol.Allowlist, &pol.Infrastructure} {
		for _, ip := range set.IPs() {
			if err := g.ProtectIP(ip); err != nil {
				return nil, err
			}
		}
		for _, mac := range set.MACs() {
			if err := g.ProtectMAC(mac); err != nil {
				return nil, err
			}
		}
	}
	if pol.GatewayIP.IsValid() || pol.GatewayMAC != "" {
		g.ProtectName("default gateway")
	}
	return &g, nil
}

// deviceDriverReady says whether a driver that acts on a device (ARP
// isolation, switch port) may be offered. Both need the gateway pinned by
// IP and MAC — with only one of them the guard cannot recognise the router
// by the other — and a complete infrastructure set.
func deviceDriverReady(pol *policy.Policy, infraErr error) error {
	if !pol.GatewayIP.IsValid() || pol.GatewayMAC == "" {
		return errors.New("GATEWAY_IP and GATEWAY_MAC must both be set so the gateway is protected by both identifiers")
	}
	if infraErr != nil {
		return fmt.Errorf("the devices this service must protect could not all be determined: %w", infraErr)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
