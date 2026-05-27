package tls

import (
	"crypto/md5"
	gotls "crypto/tls"
	"encoding/hex"
	"strconv"
	"strings"
)

var greaseValues = map[uint16]struct{}{
	0x0a0a: {}, 0x1a1a: {}, 0x2a2a: {}, 0x3a3a: {},
	0x4a4a: {}, 0x5a5a: {}, 0x6a6a: {}, 0x7a7a: {},
	0x8a8a: {}, 0x9a9a: {}, 0xaaaa: {}, 0xbaba: {},
	0xcaca: {}, 0xdada: {}, 0xeaea: {}, 0xfafa: {},
}

// JA3String returns the Salesforce JA3 string for a parsed ClientHello.
func JA3String(hello *ClientHello) string {
	if hello == nil {
		return ",,,,"
	}

	return strings.Join([]string{
		strconv.Itoa(int(hello.Version)),
		joinUint16s(filterGREASE(hello.CipherSuites), "-"),
		joinUint16s(filterGREASE(extensionIDs(hello.Extensions)), "-"),
		joinUint16s(filterGREASE(hello.SupportedCurves), "-"),
		joinUint8s(hello.SupportedPoints, "-"),
	}, ",")
}

// JA3Hash returns the MD5 digest of a JA3 string as lowercase hexadecimal.
func JA3Hash(ja3 string) string {
	digest := md5.Sum([]byte(ja3))
	return hex.EncodeToString(digest[:])
}

// JA3FromRaw parses raw ClientHello bytes and returns the JA3 string and hash.
func JA3FromRaw(raw []byte) (string, string, error) {
	hello, err := ParseClientHello(raw)
	if err != nil {
		return "", "", err
	}
	ja3 := JA3String(hello)
	return ja3, JA3Hash(ja3), nil
}

// JA3FromTLS converts crypto/tls ClientHelloInfo and returns the JA3 string and hash.
func JA3FromTLS(info *gotls.ClientHelloInfo) (string, string) {
	ja3 := JA3String(ClientHelloFromTLS(info))
	return ja3, JA3Hash(ja3)
}

func extensionIDs(extensions []Extension) []uint16 {
	ids := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		ids = append(ids, extension.Type)
	}
	return ids
}

func filterGREASE(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func isGREASE(value uint16) bool {
	_, ok := greaseValues[value]
	return ok
}

func joinUint16s(values []uint16, sep string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, sep)
}

func joinUint8s(values []uint8, sep string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, sep)
}
