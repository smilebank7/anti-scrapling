// Package http2 computes HTTP/2 and JA4H request fingerprints.
package http2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	frameTypeData         FrameType = 0x0
	frameTypeHeaders      FrameType = 0x1
	frameTypePriority     FrameType = 0x2
	frameTypeRSTStream    FrameType = 0x3
	frameTypeSettings     FrameType = 0x4
	frameTypePushPromise  FrameType = 0x5
	frameTypePing         FrameType = 0x6
	frameTypeGoAway       FrameType = 0x7
	frameTypeWindowUpdate FrameType = 0x8
	frameTypeContinuation FrameType = 0x9
)

const (
	flagHeadersPadded   = 0x8
	flagHeadersPriority = 0x20
)

var errNeedMoreData = errors.New("http2: incomplete frame data")

// FrameType identifies the HTTP/2 frame type byte.
type FrameType uint8

// Setting is one id/value entry from an HTTP/2 SETTINGS frame.
type Setting struct {
	ID    uint16
	Value uint32
}

// PriorityParam is the priority tuple encoded by PRIORITY or HEADERS frames.
type PriorityParam struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// HeadersBlock contains the header-name order decoded from an HPACK block.
type HeadersBlock struct {
	StreamID           uint32
	PseudoHeaderOrder  []string
	RegularHeaderOrder []string
	Priority           *PriorityParam
}

// Frame is the parsed subset of an HTTP/2 frame needed for fingerprinting.
type Frame struct {
	Type                  FrameType
	Flags                 uint8
	StreamID              uint32
	Settings              []Setting
	WindowUpdateIncrement uint32
	Priority              *PriorityParam
	Headers               *HeadersBlock
}

// ParseFrames parses raw HTTP/2 frame bytes into the minimal frame model used
// by the Akamai fingerprint. The client connection preface is skipped when it
// is present. Unknown frame types are retained only as their type/flags/id.
func ParseFrames(data []byte) ([]Frame, error) {
	if len(data) >= len(clientPreface) && string(data[:len(clientPreface)]) == clientPreface {
		data = data[len(clientPreface):]
	}

	frames := make([]Frame, 0)
	decoder := newHPACKNameDecoder()

	for len(data) > 0 {
		if len(data) < 9 {
			return nil, errNeedMoreData
		}

		length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		if len(data) < 9+length {
			return nil, errNeedMoreData
		}

		frame := Frame{
			Type:     FrameType(data[3]),
			Flags:    data[4],
			StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff,
		}
		payload := data[9 : 9+length]

		switch frame.Type {
		case frameTypeSettings:
			settings, err := parseSettings(payload)
			if err != nil {
				return nil, err
			}
			frame.Settings = settings
		case frameTypeWindowUpdate:
			increment, err := parseWindowUpdate(payload)
			if err != nil {
				return nil, err
			}
			frame.WindowUpdateIncrement = increment
		case frameTypePriority:
			priority, err := parsePriority(payload, frame.StreamID)
			if err != nil {
				return nil, err
			}
			frame.Priority = priority
		case frameTypeHeaders:
			headers, err := parseHeaders(payload, frame.Flags, frame.StreamID, decoder)
			if err != nil {
				return nil, err
			}
			frame.Headers = headers
		}

		frames = append(frames, frame)
		data = data[9+length:]
	}

	return frames, nil
}

func parseSettings(payload []byte) ([]Setting, error) {
	if len(payload)%6 != 0 {
		return nil, fmt.Errorf("http2: SETTINGS payload length %d is not divisible by 6", len(payload))
	}

	settings := make([]Setting, 0, len(payload)/6)
	for len(payload) > 0 {
		settings = append(settings, Setting{
			ID:    binary.BigEndian.Uint16(payload[0:2]),
			Value: binary.BigEndian.Uint32(payload[2:6]),
		})
		payload = payload[6:]
	}

	return settings, nil
}

func parseWindowUpdate(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("http2: WINDOW_UPDATE payload length %d, want 4", len(payload))
	}

	return binary.BigEndian.Uint32(payload) & 0x7fffffff, nil
}

func parsePriority(payload []byte, streamID uint32) (*PriorityParam, error) {
	if len(payload) != 5 {
		return nil, fmt.Errorf("http2: PRIORITY payload length %d, want 5", len(payload))
	}

	dependency := binary.BigEndian.Uint32(payload[0:4])
	return &PriorityParam{
		StreamID:  streamID,
		Exclusive: dependency&0x80000000 != 0,
		DependsOn: dependency & 0x7fffffff,
		Weight:    payload[4],
	}, nil
}

func parseHeaders(payload []byte, flags uint8, streamID uint32, decoder *hpackNameDecoder) (*HeadersBlock, error) {
	headers := &HeadersBlock{StreamID: streamID}

	if flags&flagHeadersPadded != 0 {
		if len(payload) == 0 {
			return nil, errNeedMoreData
		}
		padLength := int(payload[0])
		payload = payload[1:]
		if padLength > len(payload) {
			return nil, fmt.Errorf("http2: HEADERS padding length %d exceeds payload", padLength)
		}
		payload = payload[:len(payload)-padLength]
	}

	if flags&flagHeadersPriority != 0 {
		if len(payload) < 5 {
			return nil, errNeedMoreData
		}
		priority, err := parsePriority(payload[:5], streamID)
		if err != nil {
			return nil, err
		}
		headers.Priority = priority
		payload = payload[5:]
	}

	names, err := decoder.decode(payload)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if len(name) == 0 {
			continue
		}
		if name[0] == ':' {
			headers.PseudoHeaderOrder = append(headers.PseudoHeaderOrder, name[1:])
			continue
		}
		headers.RegularHeaderOrder = append(headers.RegularHeaderOrder, name)
	}

	return headers, nil
}

type hpackNameDecoder struct {
	dynamicNames []string
}

func newHPACKNameDecoder() *hpackNameDecoder {
	return &hpackNameDecoder{}
}

func (d *hpackNameDecoder) decode(block []byte) ([]string, error) {
	names := make([]string, 0)
	for len(block) > 0 {
		b := block[0]
		switch {
		case b&0x80 != 0:
			index, rest, err := readHPACKInt(block, 7)
			if err != nil {
				return nil, err
			}
			name := d.lookupName(index)
			if name != "" {
				names = append(names, name)
			}
			block = rest

		case b&0x40 != 0:
			name, rest, err := d.readLiteralName(block, 6)
			if err != nil {
				return nil, err
			}
			d.addDynamicName(name)
			if name != "" {
				names = append(names, name)
			}
			block = rest

		case b&0x20 != 0:
			_, rest, err := readHPACKInt(block, 5)
			if err != nil {
				return nil, err
			}
			block = rest

		default:
			name, rest, err := d.readLiteralName(block, 4)
			if err != nil {
				return nil, err
			}
			if name != "" {
				names = append(names, name)
			}
			block = rest
		}
	}

	return names, nil
}

func (d *hpackNameDecoder) readLiteralName(block []byte, prefix uint8) (string, []byte, error) {
	index, rest, err := readHPACKInt(block, prefix)
	if err != nil {
		return "", nil, err
	}

	var name string
	if index > 0 {
		name = d.lookupName(index)
	} else {
		name, rest, err = readHPACKString(rest)
		if err != nil {
			return "", nil, err
		}
	}

	_, rest, err = readHPACKString(rest)
	if err != nil {
		return "", nil, err
	}

	return name, rest, nil
}

func (d *hpackNameDecoder) lookupName(index uint64) string {
	if index == 0 {
		return ""
	}
	if index <= uint64(len(hpackStaticNames)) {
		return hpackStaticNames[index-1]
	}
	dynamicIndex := int(index) - len(hpackStaticNames) - 1
	if dynamicIndex >= 0 && dynamicIndex < len(d.dynamicNames) {
		return d.dynamicNames[dynamicIndex]
	}
	return ""
}

func (d *hpackNameDecoder) addDynamicName(name string) {
	if name == "" {
		return
	}
	d.dynamicNames = append([]string{name}, d.dynamicNames...)
}

func readHPACKInt(data []byte, prefix uint8) (uint64, []byte, error) {
	if len(data) == 0 {
		return 0, nil, errNeedMoreData
	}

	mask := byte((1 << prefix) - 1)
	value := uint64(data[0] & mask)
	data = data[1:]
	if value < uint64(mask) {
		return value, data, nil
	}

	shift := uint(0)
	for {
		if len(data) == 0 {
			return 0, nil, errNeedMoreData
		}
		b := data[0]
		data = data[1:]
		value += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, data, nil
		}
		shift += 7
		if shift > 56 {
			return 0, nil, errors.New("http2: HPACK integer overflow")
		}
	}
}

func readHPACKString(data []byte) (string, []byte, error) {
	if len(data) == 0 {
		return "", nil, errNeedMoreData
	}
	huffman := data[0]&0x80 != 0
	length, rest, err := readHPACKInt(data, 7)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(rest)) < length {
		return "", nil, errNeedMoreData
	}
	value := rest[:length]
	rest = rest[length:]
	if huffman {
		// The parser only needs names for fingerprinting. Standard pseudo-header
		// names are normally sent by index; if a synthetic capture Huffman-encodes
		// a literal name, leave it unidentified instead of adding a dependency.
		return "", rest, nil
	}
	return string(value), rest, nil
}

var hpackStaticNames = []string{
	":authority",
	":method",
	":method",
	":path",
	":path",
	":scheme",
	":scheme",
	":status",
	":status",
	":status",
	":status",
	":status",
	":status",
	":status",
	"accept-charset",
	"accept-encoding",
	"accept-language",
	"accept-ranges",
	"accept",
	"access-control-allow-origin",
	"age",
	"allow",
	"authorization",
	"cache-control",
	"content-disposition",
	"content-encoding",
	"content-language",
	"content-length",
	"content-location",
	"content-range",
	"content-type",
	"cookie",
	"date",
	"etag",
	"expect",
	"expires",
	"from",
	"host",
	"if-match",
	"if-modified-since",
	"if-none-match",
	"if-range",
	"if-unmodified-since",
	"last-modified",
	"link",
	"location",
	"max-forwards",
	"proxy-authenticate",
	"proxy-authorization",
	"range",
	"referer",
	"refresh",
	"retry-after",
	"server",
	"set-cookie",
	"strict-transport-security",
	"transfer-encoding",
	"user-agent",
	"vary",
	"via",
	"www-authenticate",
}
