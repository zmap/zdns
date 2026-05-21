package zdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/time/rate"
)

const rateLimitTTL = time.Second * 15

var ErrRateLimitExceeded = errors.New("rate limit exceeded")

type NameServerRateLimiter interface {
	wait(ctx context.Context, ns NameServer) error
}

type PerIPPerNameNSRateLimiter struct {
	perIPRate   rate.Limit
	perNameRate rate.Limit

	perIPRateLimitCache   *ttlcache.Cache[netip.Addr, *rate.Limiter]
	perNameRateLimitCache *ttlcache.Cache[string, *rate.Limiter]
}

func NewNameServerRateLimiter(perIPRate, perNameRate rate.Limit) *PerIPPerNameNSRateLimiter {
	rl := &PerIPPerNameNSRateLimiter{
		perIPRate:   perIPRate,
		perNameRate: perNameRate,

		perIPRateLimitCache: ttlcache.New[netip.Addr, *rate.Limiter](
			ttlcache.WithTTL[netip.Addr, *rate.Limiter](rateLimitTTL),
		),
		perNameRateLimitCache: ttlcache.New[string, *rate.Limiter](
			ttlcache.WithTTL[string, *rate.Limiter](rateLimitTTL)),
	}
	go rl.perIPRateLimitCache.Start() // starts automatic expired item deletion
	go rl.perNameRateLimitCache.Start()
	return rl
}

// reservation wraps a rate.Reservation to more easily handle nil Reservations
type reservation struct {
	r *rate.Reservation
}

func (r reservation) Delay() time.Duration {
	if r.r == nil {
		return 0
	}
	return r.r.Delay()
}

func (r reservation) Cancel() {
	if r.r != nil {
		r.r.Cancel()
	}
}

// getLimiters retrieves the associated per-IP and per-Name limiters for a given NS. If none exist, they will be created.
func (l *PerIPPerNameNSRateLimiter) getReservations(ns NameServer) (perIPReservation, perNameReservation *reservation, err error) {
	perIPReservation = &reservation{}
	perNameReservation = &reservation{}
	if len(ns.DomainName) > 0 {
		perName := l.perNameRateLimitCache.Get(ns.DomainName)
		if perName == nil {
			perName = l.perNameRateLimitCache.Set(ns.DomainName, rate.NewLimiter(l.perNameRate, 1), rateLimitTTL)
		}
		perNameReservation.r = perName.Value().Reserve()
	}
	ip, err := netip.ParseAddr(ns.IP.String())
	if err != nil {
		err = fmt.Errorf("error parsing IP address %s: %w", ns.IP.String(), err)
		return
	}
	perIP := l.perIPRateLimitCache.Get(ip)
	if perIP == nil {
		perIP = l.perIPRateLimitCache.Set(ip, rate.NewLimiter(l.perIPRate, 1), rateLimitTTL)
	}
	perIPReservation.r = perIP.Value().Reserve()
	return

}

func (l *PerIPPerNameNSRateLimiter) wait(ctx context.Context, ns NameServer) error {

	ipReservation, nameReservation, err := l.getReservations(ns)
	if err != nil {
		return err
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		canIP := remaining >= ipReservation.Delay()
		canName := remaining >= nameReservation.Delay()

		if !canIP || !canName {
			ipReservation.Cancel()
			nameReservation.Cancel()
			switch {
			case !canIP && !canName:
				return fmt.Errorf("rate limit exceeded on both a per-IP and domain name basis: %w", ErrRateLimitExceeded)
			case !canIP:
				return fmt.Errorf("rate limit exceeded on a per-IP basis: %w", ErrRateLimitExceeded)
			default:
				return fmt.Errorf("rate limit exceeded on a domain name basis: %w", ErrRateLimitExceeded)
			}
		}
	}

	delay := max(ipReservation.Delay(), nameReservation.Delay())
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		ipReservation.Cancel()
		nameReservation.Cancel()
		return ctx.Err()
	}
}
