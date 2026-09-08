package origin

// none.go — the `none` provider (TESTING ONLY, doc §5.1.3): the
// carrier dials the local WS listener directly (ws://, no TLS). It
// exists so a staging/air-gapped node can be exercised end-to-end
// before a real domain is in place. It is rejected for a public
// deployment (RejectForPublicDeploy) — a real install defaults to
// wss:// via the caddy/cdn providers.

import (
	"context"
	"fmt"
	"net"
)

// NoneProvider is the testing-only direct-WS origin.
type NoneProvider struct{}

// Configure implements OriginProvider (none mode). It validates the
// plan (loopback upstream) and returns nothing to write: no Caddy, no
// file. The direct WS URL is derived by DirectWSURL for the carrier
// config.
func (p *NoneProvider) Configure(ctx context.Context, plan Plan) error {
	if plan.Mode != ModeNone {
		return fmt.Errorf("%w: none provider requires mode none, got %q", ErrInvalidPlan, plan.Mode)
	}
	return plan.validate()
}

// DirectWSURL is the ws:// URL the carrier dials in none mode:
// ws://<upstream>/upload (the loopback listener, no TLS).
func (p *NoneProvider) DirectWSURL(plan Plan) (string, error) {
	if plan.Mode != ModeNone {
		return "", fmt.Errorf("%w: DirectWSURL requires mode none, got %q", ErrInvalidPlan, plan.Mode)
	}
	if err := plan.validate(); err != nil {
		return "", err
	}
	return "ws://" + plan.UpstreamAddr + UpstreamPath, nil
}

// Status implements OriginProvider: reports "no origin" (direct WS,
// testing only). There is no binary or file to probe.
func (p *NoneProvider) Status(ctx context.Context) (Health, error) {
	return Health{
		Mode:   ModeNone,
		Live:   false,
		Detail: "no origin (direct WS, testing only)",
	}, nil
}

// RejectForPublicDeploy is the config-validator hook that REJECTS
// `none` for a public deployment (doc §5.1.3): a public node must use
// a real domain over wss:// (caddy or cdn mode). It is called by the
// T8 CLI / T7 convergence when the deploy target is public. The
// domain is already-validated public input (not a secret), so naming
// it in the error is safe.
func (p *NoneProvider) RejectForPublicDeploy(publicDomain string) error {
	if publicDomain == "" {
		return fmt.Errorf("origin: none mode cannot be used for a public deployment (provide an upload domain and use caddy or cdn mode)")
	}
	return fmt.Errorf("origin: none mode is testing-only and cannot serve public domain %s (use caddy or cdn mode)", publicDomain)
}

// loopbackHost returns true if the host part of a host:port addr is
// loopback (helper for tests / the T8 validator).
func loopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
