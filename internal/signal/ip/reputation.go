package ip

import (
	"net"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultCacheSize = 4096

type Entry struct {
	ASN      ASNResult
	Category Category
	IsTor    bool
}

type Cache struct {
	inner *lru.Cache[string, *Entry]
}

func NewCache(size int) (*Cache, error) {
	if size <= 0 {
		size = defaultCacheSize
	}
	c, err := lru.New[string, *Entry](size)
	if err != nil {
		return nil, err
	}
	return &Cache{inner: c}, nil
}

func (c *Cache) GetOrCompute(ip net.IP) *Entry {
	key := ip.String()
	if entry, ok := c.inner.Get(key); ok {
		return entry
	}
	entry := c.compute(ip)
	c.inner.Add(key, entry)
	return entry
}

func (c *Cache) compute(ip net.IP) *Entry {
	asnResult, _ := LookupASN(ip)
	return &Entry{
		ASN:      asnResult,
		Category: Categorize(asnResult.ASN),
		IsTor:    IsTorExit(ip),
	}
}
