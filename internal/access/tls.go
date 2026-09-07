package access

import (
	"bytes"
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
		// Names the flags, not the parameters: the reader of this message is
		// holding a command line.
		return nil, fmt.Errorf("provide exactly one credential source: --pem or --p12")
	}

	var (
		cert tls.Certificate
		err  error
	)
	if bundlePath != "" {
		cert, err = loadFromPEMBundle(bundlePath)
	} else {
		cert, err = loadFromPKCS12(p12Path, p12Password)
	}
	if err != nil {
		return nil, err
	}
	if err := assertLeafFresh(cert); err != nil {
		return nil, err
	}

	cfg := BaseTLSConfig(remote, serverNameOverride)
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

// BaseTLSConfig builds everything a consumer connection needs EXCEPT the client
// credential, which the caller attaches.
//
// RootCAs stays nil, so the SERVER is verified against the system trust store.
// The gateway presents a publicly trusted certificate, not one signed by the
// tunnel CA, so pinning that CA here would reject every connection. The tunnel
// CA goes the other way: it is part of the chain we PRESENT.
// The server is always verified. There is no flag, no config field and no
// host that turns it off: this is the connection that presents a client
// certificate, so a downgraded handshake hands that credential to whatever
// answered.
func BaseTLSConfig(remote, serverNameOverride string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: resolveServerName(remote, serverNameOverride),
	}
}

// loadFromPEMBundle expects one file holding the client cert, its private key
// and at least one CA certificate, leaf first.
//
// The CA certificates are not collected into a trust pool: the server is verified
// against system roots. They are counted, because a bundle with no chain is
// broken and catching it here beats a handshake alert from the far side.
func loadFromPEMBundle(path string) (tls.Certificate, error) {
	// Carries a private key, so it is read owner-only: validated on the open
	// descriptor, symlinks refused.
	data, err := security.ReadPrivateFile(path)
	if err != nil {
		return tls.Certificate{}, classify("read pem bundle", err)
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		// --pem pointed at the store's `cert.pem` has no key, and crypto/tls
		// answers that with a sentence about PEM block types. Name the mistake
		// rather than relay it.
		if bytes.Contains(data, []byte("BEGIN CERTIFICATE")) && !bytes.Contains(data, []byte("PRIVATE KEY")) {
			// A multi-line, multi-sentence message on purpose, so ST1005's
			// single-clause rule does not apply.
			return tls.Certificate{}, fmt.Errorf( //nolint:staticcheck // ST1005
				"%s holds certificates but no private key.\n"+
					"  --pem wants ONE file containing the leaf, its chain and the key.\n"+
					"  If this came from the identity store, drop --pem entirely: "+
					"`localport access` presents a stored credential on its own.", path)
		}
		return tls.Certificate{}, classify("parse pem bundle", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf: %w", err)
	}
	// Kept on the certificate so crypto/tls does not re-parse the leaf on every
	// handshake. A long-lived access session opens many.
	cert.Leaf = leaf

	cas := 0
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
		// Compared by DER, not by serial: a serial is unique only within its own
		// CA (RFC 5280 4.1.2.2).
		if bytes.Equal(block.Bytes, cert.Certificate[0]) {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return tls.Certificate{}, fmt.Errorf("parse cert in bundle: %w", err)
		}
		cas++
	}
	if cas == 0 {
		return tls.Certificate{}, fmt.Errorf("pem bundle %s does not contain any CA certificates", path)
	}
	return cert, nil
}

// loadFromPKCS12 unpacks a .p12/.pfx archive into the client cert and its chain.
// PKCS#12 always ships a chain, so an empty one is a config error.
func loadFromPKCS12(path, password string) (tls.Certificate, error) {
	// Owner-only, like the PEM bundle. A password on an archive is not a reason to
	// let every local account read a private key: exported passwords are routinely
	// weak or shared.
	raw, err := security.ReadPrivateFile(path)
	if err != nil {
		return tls.Certificate{}, classify("read pkcs12", err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return tls.Certificate{}, classify("decode pkcs12", err)
	}
	if len(chain) == 0 {
		return tls.Certificate{}, fmt.Errorf("pkcs12 %s carries no CA chain", path)
	}
	cert := tls.Certificate{
		PrivateKey:  key,
		Leaf:        leaf,
		Certificate: [][]byte{leaf.Raw},
	}
	// Appended to the chain we PRESENT. Not added to a trust pool: the server is
	// verified against system roots.
	for _, ca := range chain {
		cert.Certificate = append(cert.Certificate, ca.Raw)
	}
	return cert, nil
}

func assertLeafFresh(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	// Both loaders set Leaf, so this parses only for a certificate built
	// elsewhere.
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse leaf: %w", err)
		}
		leaf = parsed
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

// resolveServerName picks the name the server certificate is verified against.
//
// An IP literal is returned AS the ServerName rather than blanked: crypto/tls
// refuses to handshake on an empty ServerName, and the literal is also correct,
// since crypto/tls omits SNI for an IP (RFC 6066) and VerifyHostname then
// matches the IP SANs.
func resolveServerName(remote, override string) string {
	if override != "" {
		return override
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
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
