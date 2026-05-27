package http2

import (
	"fmt"
	"strconv"
	"strings"
)

// AkamaiFingerprint contains the four parts of an Akamai HTTP/2 fingerprint.
type AkamaiFingerprint struct {
	Settings              []Setting
	WindowUpdateIncrement uint32
	Priorities            []PriorityParam
	PseudoHeaderOrder     []string
}

// String renders the fingerprint as SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO.
// This project stores SETTINGS pairs comma-separated to match test fixtures.
func (f AkamaiFingerprint) String() string {
	if len(f.Settings) == 0 && f.WindowUpdateIncrement == 0 && len(f.Priorities) == 0 && len(f.PseudoHeaderOrder) == 0 {
		return ""
	}

	settings := make([]string, 0, len(f.Settings))
	for _, setting := range f.Settings {
		settings = append(settings, fmt.Sprintf("%d:%d", setting.ID, setting.Value))
	}

	priorities := "0"
	if len(f.Priorities) > 0 {
		parts := make([]string, 0, len(f.Priorities))
		for _, priority := range f.Priorities {
			exclusive := 0
			if priority.Exclusive {
				exclusive = 1
			}
			parts = append(parts, fmt.Sprintf("%d:%d:%d:%d", priority.StreamID, exclusive, priority.DependsOn, priority.Weight))
		}
		priorities = strings.Join(parts, ",")
	}

	pseudo := make([]string, 0, len(f.PseudoHeaderOrder))
	for _, name := range f.PseudoHeaderOrder {
		code := pseudoHeaderCode(name)
		if code != "" {
			pseudo = append(pseudo, code)
		}
	}

	return strings.Join(settings, ",") + "|" + strconv.FormatUint(uint64(f.WindowUpdateIncrement), 10) + "|" + priorities + "|" + strings.Join(pseudo, ",")
}

// ComputeAkamaiFingerprint computes the Akamai HTTP/2 fingerprint from parsed
// frames. It uses the first non-empty SETTINGS frame, the first connection-level
// WINDOW_UPDATE, any priority tuples before or on HEADERS, and the first HEADERS
// pseudo-header order.
func ComputeAkamaiFingerprint(frames []Frame) string {
	fingerprint := AkamaiFingerprint{}

	for _, frame := range frames {
		switch frame.Type {
		case frameTypeSettings:
			if len(fingerprint.Settings) == 0 && len(frame.Settings) > 0 {
				fingerprint.Settings = append(fingerprint.Settings, frame.Settings...)
			}
		case frameTypeWindowUpdate:
			if fingerprint.WindowUpdateIncrement == 0 && frame.StreamID == 0 {
				fingerprint.WindowUpdateIncrement = frame.WindowUpdateIncrement
			}
		case frameTypePriority:
			if frame.Priority != nil {
				fingerprint.Priorities = append(fingerprint.Priorities, *frame.Priority)
			}
		case frameTypeHeaders:
			if frame.Headers == nil {
				continue
			}
			if frame.Headers.Priority != nil {
				fingerprint.Priorities = append(fingerprint.Priorities, *frame.Headers.Priority)
			}
			if len(fingerprint.PseudoHeaderOrder) == 0 && len(frame.Headers.PseudoHeaderOrder) > 0 {
				fingerprint.PseudoHeaderOrder = append(fingerprint.PseudoHeaderOrder, frame.Headers.PseudoHeaderOrder...)
			}
		}
	}

	return fingerprint.String()
}

// ComputeAkamaiFingerprintBytes parses raw HTTP/2 frames and computes their
// Akamai fingerprint.
func ComputeAkamaiFingerprintBytes(data []byte) (string, error) {
	frames, err := ParseFrames(data)
	if err != nil {
		return "", err
	}
	return ComputeAkamaiFingerprint(frames), nil
}

func pseudoHeaderCode(name string) string {
	switch strings.TrimPrefix(strings.ToLower(name), ":") {
	case "method":
		return "m"
	case "authority":
		return "a"
	case "scheme":
		return "s"
	case "path":
		return "p"
	default:
		return ""
	}
}
