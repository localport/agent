package connect

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// BuildTLSConfig assembles a mutual-TLS client config from PEM-encoded
// certificate, key, and CA files. The leaf certificate's NotAfter is
// checked up front so an expired cert fails with a useful message rather
// than a generic handshake error.
func BuildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
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
	}, nil
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
