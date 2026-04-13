package connect

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/localport/agent/internal/security"
)

func BuildTLSConfig(certFile, keyFile, caFile, remote, serverNameOverride string) (*tls.Config, error) {
	if err := security.ValidatePrivateKeyPermissions(keyFile); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, classify("load client cert", err)
	}
	if err := checkExpiry(cert); err != nil {
		return nil, err
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA %s: no PEM certificates found", caFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   resolveServerName(remote, serverNameOverride),
	}, nil
}

func resolveServerName(remote, override string) string {
	if override != "" {
		return override
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	// Local development convenience: certs issued for plain "localhost"
	// should still validate when users dial e.g. "db.localhost".
	if strings.HasSuffix(host, ".localhost") {
		return "localhost"
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func checkExpiry(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("client cert expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if d := time.Until(leaf.NotAfter); d < 24*time.Hour {
		fmt.Fprintf(os.Stderr, "warning: client cert expires in %s\n", d.Round(time.Minute))
	}
	return nil
}

func classify(prefix string, err error) error {
	switch {
	case os.IsNotExist(err):
		return fmt.Errorf("%s: file not found: %w", prefix, err)
	case os.IsPermission(err):
		return fmt.Errorf("%s: permission denied: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
