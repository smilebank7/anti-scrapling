package ip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCategorize_Datacenter(t *testing.T) {
	cases := []struct {
		asn  uint
		name string
	}{
		{16509, "AWS"},
		{14618, "AWS alt"},
		{39111, "AWS NoVa"},
		{15169, "GCP"},
		{396982, "GCP alt"},
		{8075, "Azure"},
		{14061, "DigitalOcean"},
		{63949, "Linode/Akamai"},
		{24940, "Hetzner"},
		{16276, "OVH"},
		{20473, "Vultr"},
	}
	for _, tc := range cases {
		assert.Equal(t, CategoryDatacenter, Categorize(tc.asn), "ASN %d (%s)", tc.asn, tc.name)
	}
}

func TestCategorize_Hosting(t *testing.T) {
	assert.Equal(t, CategoryHosting, Categorize(13335), "Cloudflare")
	assert.Equal(t, CategoryHosting, Categorize(54113), "Fastly")
}

func TestCategorize_Unknown(t *testing.T) {
	assert.Equal(t, CategoryUnknown, Categorize(0))
	assert.Equal(t, CategoryUnknown, Categorize(99999))
}
