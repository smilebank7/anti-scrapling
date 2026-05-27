package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestServerCapturesTLSClientHello(t *testing.T) {
	cert, roots, err := GenerateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error = %v", err)
	}

	captures := make(chan *ClientHelloCapture, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captures <- CaptureFromContext(r.Context())
		_, _ = w.Write([]byte("ok"))
	})

	srv := New("127.0.0.1:0", handler, &TLSConfig{Certificates: []tls.Certificate{cert}})
	errc := make(chan error, 1)
	go func() { errc <- srv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Stop(ctx); err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("Start() returned error = %v", err)
		}
	})

	addr := waitForServerAddr(t, srv)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %s", resp.Status)
	}

	select {
	case capture := <-captures:
		if capture == nil {
			t.Fatal("handler did not receive ClientHello capture")
		}
		if len(capture.Raw) == 0 {
			t.Fatal("captured ClientHello raw bytes are empty")
		}
		if len(capture.Raw) < 2 || capture.Raw[0] != 0x16 || capture.Raw[1] != 0x03 {
			t.Fatalf("captured ClientHello has unexpected prefix: % x", capture.Raw[:min(len(capture.Raw), 5)])
		}
		if capture.Info == nil {
			t.Fatal("captured ClientHelloInfo is nil")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler capture")
	}
}

func TestTLSConfigEnablesHTTP2ALPN(t *testing.T) {
	cert, _, err := GenerateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error = %v", err)
	}

	tlsConfig, err := buildTLSConfig(&TLSConfig{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}

	want := []string{"h2", "http/1.1"}
	if len(tlsConfig.NextProtos) < len(want) {
		t.Fatalf("NextProtos too short: %v", tlsConfig.NextProtos)
	}
	for i, proto := range want {
		if tlsConfig.NextProtos[i] != proto {
			t.Fatalf("NextProtos[%d] mismatch: want %q got %q in %v", i, proto, tlsConfig.NextProtos[i], tlsConfig.NextProtos)
		}
	}
}

func waitForServerAddr(t *testing.T, srv *Server) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		addr := srv.Addr()
		if addr != "127.0.0.1:0" {
			return addr
		}
		select {
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("server did not start listening")
	return ""
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
