package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// TLSConfig configures HTTPS serving. Cert and Key are PEM file paths. Config
// and Certificates are primarily useful for tests and callers with in-memory
// certificate material.
type TLSConfig struct {
	Cert         string
	Key          string
	Certificates []tls.Certificate
	Config       *tls.Config
}

// Server owns the HTTP listener and graceful shutdown path.
type Server struct {
	addr       string
	tlsCfg     *TLSConfig
	httpServer *http.Server

	mu       sync.Mutex
	listener net.Listener
}

// New constructs a Server. When tlsCfg is nil the server listens with plain
// HTTP; otherwise it terminates TLS and captures raw ClientHello bytes.
func New(addr string, handler http.Handler, tlsCfg *TLSConfig) *Server {
	if handler == nil {
		handler = http.DefaultServeMux
	}

	server := &Server{addr: addr, tlsCfg: tlsCfg}
	server.httpServer = &http.Server{
		Addr:      addr,
		Handler:   server.captureMiddleware(handler),
		ConnState: server.connState,
	}
	return server
}

// Start listens and serves until the listener is closed or serving fails.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("server: listen %q: %w", s.addr, err)
	}

	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		_ = listener.Close()
		return errors.New("server: already started")
	}
	s.listener = listener
	s.mu.Unlock()

	serveListener := listener
	if s.tlsCfg != nil {
		tlsConfig, err := buildTLSConfig(s.tlsCfg)
		if err != nil {
			_ = listener.Close()
			return err
		}
		s.httpServer.TLSConfig = tlsConfig
		serveListener = tls.NewListener(NewWrappedListener(listener), tlsConfig)
	}

	if err := s.httpServer.Serve(serveListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the server using ctx as its deadline/cancellation.
func (s *Server) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the listener address once Start has opened it. Before Start it
// returns the configured address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return s.addr
	}
	return s.listener.Addr().String()
}

func (s *Server) captureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture := captureForRequest(r); capture != nil {
			r = r.WithContext(ContextWithCapture(r.Context(), capture))
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		deleteClientHelloCapture(connectionKey(conn))
	}
}

func captureForRequest(r *http.Request) *ClientHelloCapture {
	if r == nil {
		return nil
	}

	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return loadClientHelloCapture(connectionKeyStrings(addrString(local), r.RemoteAddr))
}

func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("server: nil TLS config")
	}

	var tlsConfig *tls.Config
	if cfg.Config != nil {
		tlsConfig = cfg.Config.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}

	if len(cfg.Certificates) > 0 {
		tlsConfig.Certificates = append([]tls.Certificate(nil), cfg.Certificates...)
	}

	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("server: load TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	previousGetConfig := tlsConfig.GetConfigForClient
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && previousGetConfig == nil {
		return nil, errors.New("server: TLS config requires a certificate")
	}

	tlsConfig.NextProtos = withDefaultNextProtos(tlsConfig.NextProtos)
	captureCallback := CaptureCallback()
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		captureConfig, err := captureCallback(info)
		if err != nil {
			return nil, err
		}
		if previousGetConfig == nil {
			return captureConfig, nil
		}

		selectedConfig, err := previousGetConfig(info)
		if err != nil || selectedConfig == nil {
			return selectedConfig, err
		}
		selectedConfig = selectedConfig.Clone()
		selectedConfig.NextProtos = withDefaultNextProtos(selectedConfig.NextProtos)
		return selectedConfig, nil
	}

	return tlsConfig, nil
}

func withDefaultNextProtos(protocols []string) []string {
	defaults := []string{"h2", "http/1.1"}
	out := make([]string, 0, len(defaults)+len(protocols))
	seen := make(map[string]bool, len(defaults)+len(protocols))
	for _, proto := range defaults {
		out = append(out, proto)
		seen[proto] = true
	}
	for _, proto := range protocols {
		if proto == "" || seen[proto] {
			continue
		}
		out = append(out, proto)
		seen[proto] = true
	}
	return out
}
