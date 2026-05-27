package token

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// LoadKey loads the HMAC key from path. If the file does not exist, it
// generates a random 32-byte key, writes it to path with mode 0600, and
// returns it. Subsequent calls return the persisted key unchanged (idempotent).
func LoadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) == 0 {
			return nil, errors.New("token: key file is empty")
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("token: read key file: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("token: generate key: %w", err)
	}

	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("token: write key file: %w", err)
	}

	slog.Warn("token: generated new HMAC key — back this file up", "path", path)
	return key, nil
}
