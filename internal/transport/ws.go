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
}

func (d *WSDialer) Kind() Kind { return KindWS }

func (d *WSDialer) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	timeout := d.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   agentTLSConfig(host, ALPNWS),
			ForceAttemptHTTP2: false, // WS rides HTTP/1.1
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

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
	// Binary frames preserve the protocol bytes unchanged.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}
