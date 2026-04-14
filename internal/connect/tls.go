package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/localport/agent/internal/security"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// BuildTLSConfig assembles a mutual-TLS client config from one of two
// credential sources: a single PEM file holding cert+key+CA chain, or a
// PKCS#12 archive guarded by a password. Exactly one of bundlePath or
// p12Path must be supplied.
func BuildTLSConfig(bundlePath, p12Path, p12Password, remote, serverNameOverride string) (*tls.Config, error) {
	if !exactlyOne(bundlePath != "", p12Path != "") {
		return nil, fmt.Errorf("provide exactly one credential source: --bundle or --p12")
	}

	var (
		cert  tls.Certificate
		roots *x509.CertPool
		err   error
	)
	if bundlePath != "" {
		cert, roots, err = loadFromPEMBundle(bundlePath)
	} else {
		cert, roots, err = loadFromPKCS12(p12Path, p12Password)
	}
	if err != nil {
		return nil, err
	}
	if err := assertLeafFresh(cert); err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
		ServerName:   resolveServerName(remote, serverNameOverride),
	}, nil
}

// loadFromPEMBundle expects a single file containing the client cert, its
// private key, and at least one CA certificate. Convention: the leaf cert
// comes first; everything else not matching the leaf serial is added to
// the trust store.
func loadFromPEMBundle(path string) (tls.Certificate, *x509.CertPool, error) {
	if err := security.ValidatePrivateKeyPermissions(path); err != nil {
		return tls.Certificate{}, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, nil, classify("read pem bundle", err)
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return tls.Certificate{}, nil, classify("parse pem bundle", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse leaf: %w", err)
	}

	pool := x509.NewCertPool()
	added := 0
	rest := data
	for len(rest) > 0 {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = tail
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("parse cert in bundle: %w", err)
		}
		if c.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			continue
		}
		pool.AddCert(c)
		added++
	}
	if added == 0 {
		return tls.Certificate{}, nil, fmt.Errorf("pem bundle %s does not contain any CA certificates", path)
	}
	return cert, pool, nil
}

// loadFromPKCS12 unpacks a .p12/.pfx archive into a client cert plus the
// CA chain it carries. PKCS#12 always ships its own chain, so an empty
// chain is treated as a config error.
func loadFromPKCS12(path, password string) (tls.Certificate, *x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, nil, classify("read pkcs12", err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return tls.Certificate{}, nil, classify("decode pkcs12", err)
	}
	if len(chain) == 0 {
		return tls.Certificate{}, nil, fmt.Errorf("pkcs12 %s carries no CA chain", path)
	}
	cert := tls.Certificate{
		PrivateKey:  key,
		Leaf:        leaf,
		Certificate: [][]byte{leaf.Raw},
	}
	pool := x509.NewCertPool()
	for _, ca := range chain {
		cert.Certificate = append(cert.Certificate, ca.Raw)
		pool.AddCert(ca)
	}
	return cert, pool, nil
}

func assertLeafFresh(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
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

func resolveServerName(remote, override string) string {
	if override != "" {
		return override
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	if strings.HasSuffix(host, ".localhost") {
		return "localhost"
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func exactlyOne(flags ...bool) bool {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n == 1
}
