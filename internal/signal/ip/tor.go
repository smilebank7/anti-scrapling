package ip

import (
	"bufio"
	"bytes"
	_ "embed"
	"net"
	"strings"
)

//go:embed data/tor-exits.txt
var embeddedTorExits []byte

var torExitSet map[string]struct{}

func init() {
	torExitSet = make(map[string]struct{})
	if len(embeddedTorExits) > 0 {
		loadTorExits(embeddedTorExits)
	}
}

func loadTorExits(data []byte) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			torExitSet[ip.String()] = struct{}{}
		}
	}
}

func IsTorExit(ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, ok := torExitSet[ip.String()]
	return ok
}

func TorExitCount() int {
	return len(torExitSet)
}
