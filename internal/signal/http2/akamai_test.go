package http2

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type expectedHTTP2Profile struct {
	Profile           string  `json:"profile"`
	AkamaiFingerprint *string `json:"akamai_h2_fingerprint"`
}

func TestComputeAkamaiFingerprintFromFixtures(t *testing.T) {
	fixturePaths, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "http2", "*.expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixturePaths) == 0 {
		t.Fatal("no HTTP/2 expected fixtures found")
	}

	for _, fixturePath := range fixturePaths {
		profile := readExpectedHTTP2Profile(t, fixturePath)
		if profile.AkamaiFingerprint == nil {
			continue
		}

		t.Run(profile.Profile, func(t *testing.T) {
			frames := synthesizeFramesFromAkamai(t, *profile.AkamaiFingerprint)
			got, err := ComputeAkamaiFingerprintBytes(frames)
			if err != nil {
				t.Fatalf("ComputeAkamaiFingerprintBytes returned error: %v", err)
			}
			if got != *profile.AkamaiFingerprint {
				t.Fatalf("Akamai fingerprint mismatch\n got: %s\nwant: %s", got, *profile.AkamaiFingerprint)
			}
		})
	}
}

func TestComputeAkamaiFingerprintWithClientPreface(t *testing.T) {
	expected := "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p"
	frames := append([]byte(clientPreface), synthesizeFramesFromAkamai(t, expected)...)

	got, err := ComputeAkamaiFingerprintBytes(frames)
	if err != nil {
		t.Fatalf("ComputeAkamaiFingerprintBytes returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("Akamai fingerprint mismatch\n got: %s\nwant: %s", got, expected)
	}
}

func TestParseFramesRejectsTruncatedFrame(t *testing.T) {
	if _, err := ParseFrames([]byte{0, 0, 1, byte(frameTypeSettings)}); err == nil {
		t.Fatal("ParseFrames accepted a truncated frame")
	}
}

func readExpectedHTTP2Profile(t *testing.T, path string) expectedHTTP2Profile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	var profile expectedHTTP2Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return profile
}

func synthesizeFramesFromAkamai(t *testing.T, fingerprint string) []byte {
	t.Helper()
	parts := strings.Split(fingerprint, "|")
	if len(parts) != 4 {
		t.Fatalf("bad Akamai fingerprint %q", fingerprint)
	}

	var out []byte
	out = append(out, settingsFrame(t, parts[0])...)
	if parts[1] != "" && parts[1] != "0" {
		increment, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			t.Fatalf("parse window update %q: %v", parts[1], err)
		}
		out = append(out, windowUpdateFrame(uint32(increment))...)
	}
	if parts[2] != "" && parts[2] != "0" {
		for _, priority := range strings.Split(parts[2], ",") {
			out = append(out, priorityFrame(t, priority)...)
		}
	}
	out = append(out, headersFrame(t, parts[3])...)
	return out
}

func settingsFrame(t *testing.T, settingsPart string) []byte {
	t.Helper()
	var payload []byte
	for _, setting := range strings.Split(settingsPart, ",") {
		pair := strings.Split(setting, ":")
		if len(pair) != 2 {
			t.Fatalf("bad setting %q", setting)
		}
		id, err := strconv.ParseUint(pair[0], 10, 16)
		if err != nil {
			t.Fatalf("parse setting id %q: %v", pair[0], err)
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			t.Fatalf("parse setting value %q: %v", pair[1], err)
		}
		entry := make([]byte, 6)
		binary.BigEndian.PutUint16(entry[0:2], uint16(id))
		binary.BigEndian.PutUint32(entry[2:6], uint32(value))
		payload = append(payload, entry...)
	}
	return frame(byte(frameTypeSettings), 0, 0, payload)
}

func windowUpdateFrame(increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment)
	return frame(byte(frameTypeWindowUpdate), 0, 0, payload)
}

func priorityFrame(t *testing.T, priority string) []byte {
	t.Helper()
	parts := strings.Split(priority, ":")
	if len(parts) != 4 {
		t.Fatalf("bad priority tuple %q", priority)
	}
	streamID := parseUint32Part(t, parts[0])
	exclusive := parseUint32Part(t, parts[1])
	dependsOn := parseUint32Part(t, parts[2])
	weight := parseUint32Part(t, parts[3])
	if exclusive != 0 {
		dependsOn |= 0x80000000
	}
	payload := make([]byte, 5)
	binary.BigEndian.PutUint32(payload[0:4], dependsOn)
	payload[4] = byte(weight)
	return frame(byte(frameTypePriority), 0, streamID, payload)
}

func headersFrame(t *testing.T, pseudoPart string) []byte {
	t.Helper()
	var block []byte
	for _, code := range strings.Split(pseudoPart, ",") {
		block = append(block, literalPseudoHeader(t, code)...)
	}
	return frame(byte(frameTypeHeaders), 0x4, 1, block)
}

func literalPseudoHeader(t *testing.T, code string) []byte {
	t.Helper()
	indexByCode := map[string]byte{"m": 2, "a": 1, "s": 6, "p": 4}
	valueByCode := map[string]string{"m": "GET", "a": "example.com", "s": "https", "p": "/"}
	index, ok := indexByCode[code]
	if !ok {
		t.Fatalf("unknown pseudo-header code %q", code)
	}
	value := valueByCode[code]
	field := []byte{index, byte(len(value))}
	field = append(field, value...)
	return field
}

func parseUint32Part(t *testing.T, value string) uint32 {
	t.Helper()
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		t.Fatalf("parse uint32 %q: %v", value, err)
	}
	return uint32(parsed)
}

func frame(frameType byte, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	copy(frame[9:], payload)
	return frame
}
