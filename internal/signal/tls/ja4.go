package tls

import (
	"crypto/sha256"
	gotls "crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const tlsEmptyRenegotiationInfoSCSV = 0x00ff

// JA4String returns the FoxIO JA4 TLS fingerprint for a parsed ClientHello.
func JA4String(hello *ClientHello) string {
	if hello == nil {
		hello = &ClientHello{}
	}

	ciphers := filterJA4Ciphers(hello.CipherSuites)
	extensions := filterGREASE(extensionIDs(hello.Extensions))

	prefix := fmt.Sprintf(
		"t%s%s%02d%02d%s",
		ja4TLSVersion(maxTLSVersion(hello)),
		ja4SNIType(hello),
		len(ciphers),
		len(extensions),
		ja4ALPN(hello.SupportedProtos),
	)

	cipherHash := sha256Truncated12(joinUint16s(sortedUint16s(ciphers), ","))
	extensionHash := sha256Truncated12(ja4ExtensionHashInput(extensions, hello.SignatureAlgorithms))

	return prefix + "_" + cipherHash + "_" + extensionHash
}

// JA4FromRaw parses raw ClientHello bytes and returns the JA4 fingerprint.
func JA4FromRaw(raw []byte) (string, error) {
	hello, err := ParseClientHello(raw)
	if err != nil {
		return "", err
	}
	return JA4String(hello), nil
}

// JA4FromTLS converts crypto/tls ClientHelloInfo and returns the JA4 fingerprint.
func JA4FromTLS(info *gotls.ClientHelloInfo) string {
	return JA4String(ClientHelloFromTLS(info))
}

func filterJA4Ciphers(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if isGREASE(value) || value == tlsEmptyRenegotiationInfoSCSV {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func maxTLSVersion(hello *ClientHello) uint16 {
	maxVersion := hello.Version
	for _, version := range hello.SupportedVersions {
		if isGREASE(version) {
			continue
		}
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion
}

func ja4TLSVersion(version uint16) string {
	switch version {
	case gotls.VersionTLS13:
		return "13"
	case gotls.VersionTLS12:
		return "12"
	case gotls.VersionTLS11:
		return "11"
	case gotls.VersionTLS10:
		return "10"
	default:
		return "00"
	}
}

func ja4SNIType(hello *ClientHello) string {
	if hello.ServerName == "" {
		return "i"
	}
	return "d"
}

func ja4ALPN(protocols []string) string {
	if len(protocols) == 0 || protocols[0] == "" {
		return "00"
	}
	protocol := protocols[0]
	return string([]byte{protocol[0], protocol[len(protocol)-1]})
}

func ja4ExtensionHashInput(extensions []uint16, signatureAlgorithms []uint16) string {
	filtered := make([]uint16, 0, len(extensions)+len(signatureAlgorithms))
	for _, extension := range extensions {
		if extension == 0 || extension == 16 {
			continue
		}
		filtered = append(filtered, extension)
	}

	filtered = sortedUint16s(filtered)
	filtered = append(filtered, signatureAlgorithms...)
	return joinUint16s(filtered, ",")
}

func sortedUint16s(values []uint16) []uint16 {
	sorted := append([]uint16(nil), values...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	return sorted
}

func sha256Truncated12(value string) string {
	digest := sha256.Sum256([]byte(value))
	return strings.ToLower(hex.EncodeToString(digest[:]))[:12]
}
