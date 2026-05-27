// Package ip implements IP-reputation signal detection: ASN lookup, datacenter
// categorization, and Tor exit-node matching.
package ip

import (
	_ "embed"
	"fmt"
	"net"
	"net/netip"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

//go:embed data/asn.mmdb
var embeddedASNDB []byte

type asnRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// ASNResult holds the outcome of an ASN lookup.
type ASNResult struct {
	ASN uint
	Org string
}

type fallbackEntry struct {
	prefix netip.Prefix
	asn    uint
	org    string
}

var (
	db            *maxminddb.Reader
	fallbackTable []fallbackEntry
)

func init() {
	buildFallbackTable()

	if len(embeddedASNDB) == 0 {
		return
	}
	r, err := maxminddb.FromBytes(embeddedASNDB)
	if err == nil {
		db = r
	}
	// Silently ignore corrupt/invalid mmdb: fallbackTable handles the gap.
}

func buildFallbackTable() {
	raw := []struct {
		cidr string
		asn  uint
		org  string
	}{
		// AWS (AS16509, AS14618, AS39111)
		{"3.0.0.0/8", 16509, "Amazon.com Inc."},
		{"18.0.0.0/8", 14618, "Amazon Technologies Inc."},
		{"52.0.0.0/8", 16509, "Amazon.com Inc."},
		{"54.0.0.0/8", 16509, "Amazon.com Inc."},
		{"100.24.0.0/13", 39111, "Amazon Data Services NoVa"},
		// GCP (AS15169, AS396982)
		{"34.0.0.0/8", 15169, "Google LLC"},
		{"35.0.0.0/8", 15169, "Google LLC"},
		{"104.196.0.0/14", 396982, "Google LLC"},
		// Azure (AS8075)
		{"20.0.0.0/8", 8075, "Microsoft Corporation"},
		{"40.0.0.0/8", 8075, "Microsoft Corporation"},
		// DigitalOcean (AS14061)
		{"67.205.0.0/16", 14061, "DigitalOcean LLC"},
		{"68.183.0.0/16", 14061, "DigitalOcean LLC"},
		{"157.245.0.0/16", 14061, "DigitalOcean LLC"},
		// Linode / Akamai Connected Cloud (AS63949)
		{"45.33.0.0/17", 63949, "Akamai Connected Cloud"},
		{"139.162.0.0/16", 63949, "Akamai Connected Cloud"},
		// Hetzner (AS24940)
		{"5.9.0.0/16", 24940, "Hetzner Online GmbH"},
		{"88.99.0.0/16", 24940, "Hetzner Online GmbH"},
		{"195.201.0.0/16", 24940, "Hetzner Online GmbH"},
		// OVH (AS16276)
		{"5.135.0.0/16", 16276, "OVH SAS"},
		{"91.121.0.0/16", 16276, "OVH SAS"},
		// Vultr (AS20473)
		{"45.63.0.0/16", 20473, "Vultr Holdings LLC"},
		{"45.77.0.0/16", 20473, "Vultr Holdings LLC"},
		// Cloudflare (AS13335) — CDN/hosting
		{"1.1.1.0/24", 13335, "Cloudflare Inc."},
		{"104.16.0.0/13", 13335, "Cloudflare Inc."},
	}

	for _, e := range raw {
		p, err := netip.ParsePrefix(e.cidr)
		if err != nil {
			continue
		}
		fallbackTable = append(fallbackTable, fallbackEntry{
			prefix: p.Masked(),
			asn:    e.asn,
			org:    e.org,
		})
	}
}

// LookupASN returns the ASN info for ip. Queries the embedded MaxMind MMDB
// when available, otherwise falls back to the hardcoded provider table.
// A zero-value result (ASN == 0) means unrecognised — not an error.
func LookupASN(ip net.IP) (ASNResult, error) {
	if ip == nil {
		return ASNResult{}, fmt.Errorf("ip: nil IP address")
	}
	if db != nil {
		var rec asnRecord
		if err := db.Lookup(ip, &rec); err == nil && rec.AutonomousSystemNumber != 0 {
			return ASNResult{
				ASN: rec.AutonomousSystemNumber,
				Org: rec.AutonomousSystemOrganization,
			}, nil
		}
	}
	return lookupFallback(ip)
}

func lookupFallback(ip net.IP) (ASNResult, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ASNResult{}, fmt.Errorf("ip: cannot parse address %v", ip)
	}
	addr = addr.Unmap() // normalise IPv4-mapped IPv6 before prefix matching
	for _, e := range fallbackTable {
		if e.prefix.Contains(addr) {
			return ASNResult{ASN: e.asn, Org: e.org}, nil
		}
	}
	return ASNResult{}, nil
}
