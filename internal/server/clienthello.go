package server

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
)

const maxClientHelloBytes = 8 << 10

var clientHelloCaptures sync.Map

// ClientHelloCapture contains the raw TLS ClientHello record and parsed info
// observed for a single connection.
type ClientHelloCapture struct {
	Raw  []byte
	Info *tls.ClientHelloInfo
}

// CaptureCallback returns a tls.Config.GetConfigForClient callback that stores
// ClientHello captures keyed by conn.LocalAddr()+conn.RemoteAddr().
func CaptureCallback() func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if info == nil || info.Conn == nil {
			return nil, nil
		}

		key := connectionKey(info.Conn)
		if key == "" {
			return nil, nil
		}

		var raw []byte
		if wrapped, ok := info.Conn.(interface{ RawClientHello() []byte }); ok {
			raw = wrapped.RawClientHello()
		}

		clientHelloCaptures.Store(key, &ClientHelloCapture{
			Raw:  append([]byte(nil), raw...),
			Info: info,
		})
		return nil, nil
	}
}

// WrappedConn records the first bytes read from a connection so the TLS
// ClientHello can be inspected during handshake callbacks.
type WrappedConn struct {
	net.Conn

	mu  sync.Mutex
	raw []byte
}

// NewWrappedConn returns a connection that records up to 8KiB from early reads.
func NewWrappedConn(conn net.Conn) *WrappedConn {
	return &WrappedConn{Conn: conn}
}

func (c *WrappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.record(p[:n])
	}
	return n, err
}

// RawClientHello returns a defensive copy of the captured TLS ClientHello bytes.
func (c *WrappedConn) RawClientHello() []byte {
	c.mu.Lock()
	raw := append([]byte(nil), c.raw...)
	c.mu.Unlock()

	if len(raw) >= 5 && raw[0] == 0x16 {
		recordLen := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) >= 5+recordLen {
			return raw[:5+recordLen]
		}
	}
	return raw
}

func (c *WrappedConn) record(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.raw) >= maxClientHelloBytes {
		return
	}
	remaining := maxClientHelloBytes - len(c.raw)
	if len(data) > remaining {
		data = data[:remaining]
	}
	c.raw = append(c.raw, data...)
}

type WrappedListener struct {
	net.Listener
}

func NewWrappedListener(listener net.Listener) *WrappedListener {
	return &WrappedListener{Listener: listener}
}

func (l *WrappedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewWrappedConn(conn), nil
}

func loadClientHelloCapture(key string) *ClientHelloCapture {
	if key == "" {
		return nil
	}
	value, ok := clientHelloCaptures.Load(key)
	if !ok {
		return nil
	}
	capture, ok := value.(*ClientHelloCapture)
	if !ok || capture == nil {
		return nil
	}
	return cloneCapture(capture)
}

func deleteClientHelloCapture(key string) {
	if key != "" {
		clientHelloCaptures.Delete(key)
	}
}

func cloneCapture(capture *ClientHelloCapture) *ClientHelloCapture {
	if capture == nil {
		return nil
	}
	return &ClientHelloCapture{
		Raw:  append([]byte(nil), capture.Raw...),
		Info: capture.Info,
	}
}

func connectionKey(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	return connectionKeyStrings(addrString(conn.LocalAddr()), addrString(conn.RemoteAddr()))
}

func connectionKeyStrings(local, remote string) string {
	if local == "" || remote == "" {
		return ""
	}
	return local + remote
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
