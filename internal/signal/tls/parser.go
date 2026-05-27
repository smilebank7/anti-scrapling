package tls

import (
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	tlsHandshakeRecordType = 22
	clientHelloType        = 1
	defaultJA3Version      = uint16(gotls.VersionTLS12)
)

// Extension is one TLS ClientHello extension in wire order.
type Extension struct {
	// Type is the IANA TLS extension type identifier.
	Type uint16
	// Data is the raw extension payload, excluding the type and length prefix.
	Data []byte
}

// ClientHello is the parsed subset of a TLS ClientHello needed for JA3/JA4.
type ClientHello struct {
	// Version is the ClientHello legacy_version field used by JA3.
	Version uint16
	// Random is the 32-byte ClientHello random.
	Random []byte
	// SessionID is the legacy session identifier sent by the client.
	SessionID []byte
	// CipherSuites are the offered cipher suites in wire order.
	CipherSuites []uint16
	// CompressionMethods are the legacy compression methods in wire order.
	CompressionMethods []byte
	// Extensions are the ClientHello extensions in wire order.
	Extensions []Extension
	// SupportedCurves are extension 10 supported groups in wire order.
	SupportedCurves []uint16
	// SupportedPoints are extension 11 EC point formats in wire order.
	SupportedPoints []uint8
	// SupportedProtos are extension 16 ALPN protocol names in wire order.
	SupportedProtos []string
	// SupportedVersions are extension 43 TLS versions in wire order.
	SupportedVersions []uint16
	// SignatureAlgorithms are extension 13 signature schemes in wire order.
	SignatureAlgorithms []uint16
	// ServerName is the first host_name value from extension 0, if present.
	ServerName string
}

// ParseClientHello parses a TLS record or raw handshake containing a ClientHello.
func ParseClientHello(raw []byte) (*ClientHello, error) {
	body, err := clientHelloBody(raw)
	if err != nil {
		return nil, err
	}

	r := byteReader{data: body}
	legacyVersion, err := r.uint16()
	if err != nil {
		return nil, fmt.Errorf("parse clienthello version: %w", err)
	}

	random, err := r.bytes(32)
	if err != nil {
		return nil, fmt.Errorf("parse clienthello random: %w", err)
	}

	sessionIDLen, err := r.uint8()
	if err != nil {
		return nil, fmt.Errorf("parse session id length: %w", err)
	}
	sessionID, err := r.bytes(int(sessionIDLen))
	if err != nil {
		return nil, fmt.Errorf("parse session id: %w", err)
	}

	cipherBytesLen, err := r.uint16()
	if err != nil {
		return nil, fmt.Errorf("parse cipher suite length: %w", err)
	}
	if cipherBytesLen%2 != 0 {
		return nil, fmt.Errorf("parse cipher suites: odd length %d", cipherBytesLen)
	}
	cipherBytes, err := r.bytes(int(cipherBytesLen))
	if err != nil {
		return nil, fmt.Errorf("parse cipher suites: %w", err)
	}
	cipherSuites := make([]uint16, 0, len(cipherBytes)/2)
	for i := 0; i < len(cipherBytes); i += 2 {
		cipherSuites = append(cipherSuites, binary.BigEndian.Uint16(cipherBytes[i:i+2]))
	}

	compressionLen, err := r.uint8()
	if err != nil {
		return nil, fmt.Errorf("parse compression length: %w", err)
	}
	compressionMethods, err := r.bytes(int(compressionLen))
	if err != nil {
		return nil, fmt.Errorf("parse compression methods: %w", err)
	}

	hello := &ClientHello{
		Version:            legacyVersion,
		Random:             cloneBytes(random),
		SessionID:          cloneBytes(sessionID),
		CipherSuites:       cipherSuites,
		CompressionMethods: cloneBytes(compressionMethods),
	}

	if r.remaining() == 0 {
		return hello, nil
	}

	extensionsLen, err := r.uint16()
	if err != nil {
		return nil, fmt.Errorf("parse extensions length: %w", err)
	}
	extensionsData, err := r.bytes(int(extensionsLen))
	if err != nil {
		return nil, fmt.Errorf("parse extensions: %w", err)
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("parse clienthello: %d trailing bytes", r.remaining())
	}

	if err := hello.parseExtensions(extensionsData); err != nil {
		return nil, err
	}

	return hello, nil
}

// ClientHelloFromTLS converts crypto/tls ClientHelloInfo into the local model.
func ClientHelloFromTLS(info *gotls.ClientHelloInfo) *ClientHello {
	hello := &ClientHello{Version: defaultJA3Version}
	if info == nil {
		return hello
	}

	hello.CipherSuites = cloneUint16s(info.CipherSuites)
	hello.ServerName = info.ServerName
	hello.SupportedPoints = cloneBytes(info.SupportedPoints)
	hello.SupportedProtos = append([]string(nil), info.SupportedProtos...)
	hello.SupportedVersions = cloneUint16s(info.SupportedVersions)

	hello.SupportedCurves = make([]uint16, 0, len(info.SupportedCurves))
	for _, curve := range info.SupportedCurves {
		hello.SupportedCurves = append(hello.SupportedCurves, uint16(curve))
	}

	hello.SignatureAlgorithms = make([]uint16, 0, len(info.SignatureSchemes))
	for _, scheme := range info.SignatureSchemes {
		hello.SignatureAlgorithms = append(hello.SignatureAlgorithms, uint16(scheme))
	}

	if extensionIDs := clientHelloInfoExtensions(info); len(extensionIDs) > 0 {
		hello.Extensions = make([]Extension, 0, len(extensionIDs))
		for _, extensionID := range extensionIDs {
			hello.Extensions = append(hello.Extensions, Extension{Type: extensionID})
		}
	} else {
		hello.Extensions = inferredExtensions(hello)
	}

	return hello
}

func clientHelloInfoExtensions(_ *gotls.ClientHelloInfo) []uint16 {
	// crypto/tls.ClientHelloInfo did not expose extension IDs until Go 1.24.
	// This module targets Go 1.23, so JA3/JA4 from ClientHelloInfo falls back to
	// inferred extension IDs from the exported parsed fields.
	return nil
}

func clientHelloBody(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty clienthello")
	}

	if len(raw) >= 5 && raw[0] == tlsHandshakeRecordType {
		recordLen := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+recordLen {
			return nil, fmt.Errorf("truncated TLS record: need %d bytes, got %d", 5+recordLen, len(raw))
		}
		return handshakeBody(raw[5 : 5+recordLen])
	}

	return handshakeBody(raw)
}

func handshakeBody(handshake []byte) ([]byte, error) {
	if len(handshake) < 4 {
		return nil, fmt.Errorf("truncated handshake header: got %d bytes", len(handshake))
	}
	if handshake[0] != clientHelloType {
		return nil, fmt.Errorf("unexpected handshake type %d", handshake[0])
	}

	handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+handshakeLen {
		return nil, fmt.Errorf("truncated ClientHello: need %d bytes, got %d", 4+handshakeLen, len(handshake))
	}
	return handshake[4 : 4+handshakeLen], nil
}

func (hello *ClientHello) parseExtensions(data []byte) error {
	r := byteReader{data: data}
	for r.remaining() > 0 {
		extensionType, err := r.uint16()
		if err != nil {
			return fmt.Errorf("parse extension type: %w", err)
		}
		extensionLen, err := r.uint16()
		if err != nil {
			return fmt.Errorf("parse extension %d length: %w", extensionType, err)
		}
		extensionData, err := r.bytes(int(extensionLen))
		if err != nil {
			return fmt.Errorf("parse extension %d data: %w", extensionType, err)
		}

		extension := Extension{Type: extensionType, Data: cloneBytes(extensionData)}
		hello.Extensions = append(hello.Extensions, extension)
		hello.parseKnownExtension(extension)
	}
	return nil
}

func (hello *ClientHello) parseKnownExtension(extension Extension) {
	switch extension.Type {
	case 0:
		hello.ServerName = parseServerName(extension.Data)
	case 10:
		hello.SupportedCurves = parseUint16Vector16(extension.Data)
	case 11:
		hello.SupportedPoints = parseUint8Vector8(extension.Data)
	case 13:
		hello.SignatureAlgorithms = parseUint16Vector16(extension.Data)
	case 16:
		hello.SupportedProtos = parseALPN(extension.Data)
	case 43:
		hello.SupportedVersions = parseSupportedVersions(extension.Data)
	}
}

func parseServerName(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen > len(data)-2 {
		return ""
	}

	off := 2
	end := 2 + listLen
	for off < end {
		if end-off < 3 {
			return ""
		}
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if nameLen > end-off {
			return ""
		}
		if nameType == 0 {
			return string(data[off : off+nameLen])
		}
		off += nameLen
	}
	return ""
}

func parseUint16Vector16(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	vectorLen := int(binary.BigEndian.Uint16(data[:2]))
	if vectorLen > len(data)-2 || vectorLen%2 != 0 {
		return nil
	}
	values := make([]uint16, 0, vectorLen/2)
	for off := 2; off < 2+vectorLen; off += 2 {
		values = append(values, binary.BigEndian.Uint16(data[off:off+2]))
	}
	return values
}

func parseUint8Vector8(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	vectorLen := int(data[0])
	if vectorLen > len(data)-1 {
		return nil
	}
	return cloneBytes(data[1 : 1+vectorLen])
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	vectorLen := int(data[0])
	if vectorLen > len(data)-1 || vectorLen%2 != 0 {
		return nil
	}
	values := make([]uint16, 0, vectorLen/2)
	for off := 1; off < 1+vectorLen; off += 2 {
		values = append(values, binary.BigEndian.Uint16(data[off:off+2]))
	}
	return values
}

func parseALPN(data []byte) []string {
	if protocols, ok := parseALPNStandard(data); ok {
		return protocols
	}
	if protocols, ok := parseALPNTwoByteLengths(data); ok {
		return protocols
	}
	return nil
}

func parseALPNStandard(data []byte) ([]string, bool) {
	if len(data) < 2 {
		return nil, false
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen != len(data)-2 {
		return nil, false
	}

	protocols := make([]string, 0, 2)
	for off := 2; off < len(data); {
		protocolLen := int(data[off])
		off++
		if protocolLen == 0 || protocolLen > len(data)-off {
			return nil, false
		}
		protocols = append(protocols, string(data[off:off+protocolLen]))
		off += protocolLen
	}
	return protocols, len(protocols) > 0
}

func parseALPNTwoByteLengths(data []byte) ([]string, bool) {
	if len(data) < 2 {
		return nil, false
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen != len(data)-2 {
		return nil, false
	}

	protocols := make([]string, 0, 2)
	for off := 2; off < len(data); {
		if len(data)-off < 2 {
			return nil, false
		}
		protocolLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if protocolLen == 0 || protocolLen > len(data)-off {
			return nil, false
		}
		protocols = append(protocols, string(data[off:off+protocolLen]))
		off += protocolLen
	}
	return protocols, len(protocols) > 0
}

func inferredExtensions(hello *ClientHello) []Extension {
	extensionIDs := make([]uint16, 0, 6)
	if hello.ServerName != "" {
		extensionIDs = append(extensionIDs, 0)
	}
	if len(hello.SupportedCurves) > 0 {
		extensionIDs = append(extensionIDs, 10)
	}
	if len(hello.SupportedPoints) > 0 {
		extensionIDs = append(extensionIDs, 11)
	}
	if len(hello.SignatureAlgorithms) > 0 {
		extensionIDs = append(extensionIDs, 13)
	}
	if len(hello.SupportedProtos) > 0 {
		extensionIDs = append(extensionIDs, 16)
	}
	if len(hello.SupportedVersions) > 0 {
		extensionIDs = append(extensionIDs, 43)
	}

	extensions := make([]Extension, 0, len(extensionIDs))
	for _, extensionID := range extensionIDs {
		extensions = append(extensions, Extension{Type: extensionID})
	}
	return extensions
}

type byteReader struct {
	data []byte
	off  int
}

func (r *byteReader) remaining() int {
	return len(r.data) - r.off
}

func (r *byteReader) uint8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, errors.New("unexpected EOF")
	}
	value := r.data[r.off]
	r.off++
	return value, nil
}

func (r *byteReader) uint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errors.New("unexpected EOF")
	}
	value := binary.BigEndian.Uint16(r.data[r.off : r.off+2])
	r.off += 2
	return value, nil
}

func (r *byteReader) bytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("negative length")
	}
	if r.remaining() < length {
		return nil, errors.New("unexpected EOF")
	}
	value := r.data[r.off : r.off+length]
	r.off += length
	return value, nil
}

func cloneBytes[T ~byte](values []T) []T {
	if values == nil {
		return nil
	}
	return append([]T(nil), values...)
}

func cloneUint16s(values []uint16) []uint16 {
	if values == nil {
		return nil
	}
	return append([]uint16(nil), values...)
}
