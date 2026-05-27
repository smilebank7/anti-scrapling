package ip

import (
	"fmt"
	"net"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

type Collector struct {
	cache *Cache
}

func New(cacheSize int) (*Collector, error) {
	cache, err := NewCache(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("ip collector: %w", err)
	}
	return &Collector{cache: cache}, nil
}

func (c *Collector) Name() string { return "ip" }

func (c *Collector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	ip := parseRemoteIP(ctx.RemoteIP)
	if ip == nil {
		return nil, nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil, nil
	}

	entry := c.cache.GetOrCompute(ip)

	var signals []types.Signal

	if entry.IsTor {
		signals = append(signals, types.Signal{
			Name:   "tor_exit",
			Score:  50,
			Reason: "IP is a known Tor exit node",
			Detail: map[string]any{"ip": ip.String()},
		})
	}

	switch entry.Category {
	case CategoryDatacenter:
		signals = append(signals, types.Signal{
			Name:   "datacenter_ip",
			Score:  30,
			Reason: fmt.Sprintf("ASN %d (%s)", entry.ASN.ASN, entry.ASN.Org),
			Detail: map[string]any{
				"asn":      entry.ASN.ASN,
				"org":      entry.ASN.Org,
				"category": string(entry.Category),
			},
		})
	case CategoryMobile:
		signals = append(signals, types.Signal{
			Name:   "mobile_ip",
			Score:  -5,
			Reason: fmt.Sprintf("ASN %d (%s)", entry.ASN.ASN, entry.ASN.Org),
			Detail: map[string]any{
				"asn":      entry.ASN.ASN,
				"org":      entry.ASN.Org,
				"category": string(entry.Category),
			},
		})
	case CategoryResidential:
		signals = append(signals, types.Signal{
			Name:   "residential_ip",
			Score:  0,
			Reason: fmt.Sprintf("ASN %d (%s)", entry.ASN.ASN, entry.ASN.Org),
			Detail: map[string]any{
				"asn":      entry.ASN.ASN,
				"org":      entry.ASN.Org,
				"category": string(entry.Category),
			},
		})
	}

	return signals, nil
}

func parseRemoteIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}
