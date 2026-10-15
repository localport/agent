package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// WSDialer establishes a WebSocket-over-TLS connection with ALPN
// localport-ws/1 and returns a net.Conn view of the resulting binary
// message stream. TLS 1.3 minimum, full server-cert verification.
type WSDialer struct {
	DialTimeout time.Duration
	Path        string
	ServerName  string // SNI override; empty = derive from dial host
}

func (d *WSDialer) Kind() Kind { return KindWS }

func (d *WSDialer) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	timeout := d.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// dialed is the remote address of this dial, stored in lastGood once the
	// upgrade, and so the TLS handshake, succeeds.
	var dialed net.Addr
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	httpClient := wsHTTPClient(&http.Transport{
		TLSClientConfig:   agentTLSConfig(d.ServerName, host, ALPNWS),
		ForceAttemptHTTP2: false, // WS rides HTTP/1.1
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, p := SplitHostPort(addr)
			conn, err := dialEdge(ctx, dialer, h, p)
			if err == nil {
				dialed = conn.RemoteAddr()
			}
			return conn, err
		},
	})

	path := d.Path
	if path == "" {
		path = DefaultWSPath
	}
	url := "wss://" + net.JoinHostPort(host, port) + path

	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", url, err)
	}
	if dialed != nil {
		lastGood.remember(host, dialed)
	}
	// Binary frames carry the protocol bytes unchanged. The context passed here
	// bounds the connection lifetime, so it cannot be the dial context.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// wsHTTPClient returns the client for the WebSocket upgrade. A 3xx is returned
// as is, the upgrade never follows Location to another host.
func wsHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
