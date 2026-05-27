package ip

// Category classifies an ASN's network type.
type Category string

const (
	CategoryDatacenter  Category = "datacenter"
	CategoryResidential Category = "residential"
	CategoryMobile      Category = "mobile"
	CategoryHosting     Category = "hosting"
	CategoryUnknown     Category = "unknown"
)

var knownASNCategories = map[uint]Category{
	// AWS (AS16509, AS14618, AS39111)
	16509: CategoryDatacenter,
	14618: CategoryDatacenter,
	39111: CategoryDatacenter,
	// GCP (AS15169, AS396982)
	15169:  CategoryDatacenter,
	396982: CategoryDatacenter,
	// Azure (AS8075)
	8075: CategoryDatacenter,
	// DigitalOcean (AS14061)
	14061: CategoryDatacenter,
	// Linode / Akamai Connected Cloud (AS63949)
	63949: CategoryDatacenter,
	// Hetzner (AS24940)
	24940: CategoryDatacenter,
	// OVH (AS16276)
	16276: CategoryDatacenter,
	// Vultr (AS20473)
	20473: CategoryDatacenter,
	// Cloudflare (AS13335)
	13335: CategoryHosting,
	// Fastly (AS54113)
	54113: CategoryHosting,
	// Akamai CDN (AS20940)
	20940: CategoryHosting,
}

func Categorize(asn uint) Category {
	if asn == 0 {
		return CategoryUnknown
	}
	if cat, ok := knownASNCategories[asn]; ok {
		return cat
	}
	return CategoryUnknown
}
