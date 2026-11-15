package access

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// BuildTLSConfig builds a mutual TLS client config from exactly one of
// pemPath (cert, key and CA chain in one file) or p12Path (a password
// protected PKCS#12 archive).
func BuildTLSConfig(pemPath, p12Path, p12Password, remote, serverNameOverride string) (*tls.Config, error) {
	if !exactlyOne(pemPath != "", p12Path != "") {
		return nil, errors.New("provide exactly one credential source: --pem or --p12")
	}

	var (
		cert tls.Certificate
		err  error
	)
	if pemPath != "" {
		cert, err = loadPEM(pemPath)
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

// BaseTLSConfig returns the TLS config for a consumer connection without a
// client certificate. The caller attaches the credential.
//
// RootCAs is nil because the edge presents a publicly trusted certificate.
// The tunnel CA belongs to the client chain and does not verify the server.
func BaseTLSConfig(remote, serverNameOverride string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: resolveServerName(remote, serverNameOverride),
	}
}

// loadPEM reads one file holding the client cert, its private key and at
// least one CA certificate, leaf first.
//
// The CA certificates form the presented chain and are not used for server
// verification. A file without a chain is rejected here, before the edge
// fails the handshake.
func loadPEM(path string) (tls.Certificate, error) {
	// The file holds a private key. It must be owner-only, is checked on the
	// open descriptor and must not be a symlink.
	data, err := security.ReadPrivateFile(path)
	if err != nil {
		return tls.Certificate{}, errcode.New(errcode.ClientCertUnusable).With(err, "read pem file")
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		// The identity store's certificate file has no key. crypto/tls reports
		// that as a PEM block type error, so replace it with a specific
		// message.
		if bytes.Contains(data, []byte("BEGIN CERTIFICATE")) && !bytes.Contains(data, []byte("PRIVATE KEY")) {
			return tls.Certificate{}, errcode.New(errcode.ClientCertUnusable).With(nil,
				path+" holds certificates but no private key\n"+
					"  --pem wants ONE file containing the leaf, its chain and the key.\n"+
					"  If this came from the identity store, drop --pem entirely: "+
					"`localport access` presents a stored credential on its own.")
		}
		return tls.Certificate{}, unparsable(path, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, unparsable(path, err)
	}
	// Set Leaf so crypto/tls does not parse it on each handshake.
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
		// Compare DER. A serial is unique only within its CA (RFC 5280
		// 4.1.2.2).
		if bytes.Equal(block.Bytes, cert.Certificate[0]) {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return tls.Certificate{}, unparsable(path, err)
		}
		cas++
	}
	if cas == 0 {
		return tls.Certificate{}, errcode.New(errcode.ClientCertUnusable).With(nil, path+" holds no CA certificate")
	}
	return cert, nil
}

// loadFromPKCS12 unpacks a .p12/.pfx archive into the client cert and its
// chain. An empty chain is a config error.
func loadFromPKCS12(path, password string) (tls.Certificate, error) {
	// Owner-only, as for PEM. Archive passwords are often weak or shared.
	raw, err := security.ReadPrivateFile(path)
	if err != nil {
		return tls.Certificate{}, errcode.New(errcode.ClientCertUnusable).With(err, "read pkcs12")
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return tls.Certificate{}, unparsable(path, err)
	}
	if len(chain) == 0 {
		return tls.Certificate{}, errcode.New(errcode.ClientCertUnusable).With(nil, path+" carries no CA chain")
	}
	cert := tls.Certificate{
		PrivateKey:  key,
		Leaf:        leaf,
		Certificate: [][]byte{leaf.Raw},
	}
	// CA certificates extend the presented chain. The server is verified
	// against system roots.
	for _, ca := range chain {
		cert.Certificate = append(cert.Certificate, ca.Raw)
	}
	return cert, nil
}

func assertLeafFresh(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errcode.New(errcode.ClientCertUnusable).With(nil, "the certificate is empty")
	}
	// Both loaders set Leaf. Parse only for certificates built elsewhere.
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return errcode.New(errcode.ClientCertUnusable).With(err, "parse the leaf certificate")
		}
		leaf = parsed
	}
	if now := time.Now(); now.Before(leaf.NotBefore) {
		// Usually a wrong clock. A device without RTC or NTP boots in the past.
		return errcode.New(errcode.ClientCertUnusable).With(nil, fmt.Sprintf("not valid until %s, and this machine's clock reads %s",
			leaf.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339)))

	}
	if time.Now().After(leaf.NotAfter) {
		return errcode.New(errcode.ClientCertUnusable).With(nil, "expired at "+leaf.NotAfter.Format(time.RFC3339))
	}
	if d := time.Until(leaf.NotAfter); d < 24*time.Hour {
		fmt.Fprintf(os.Stderr, "warning: client cert expires in %s\n", d.Round(time.Minute))
	}
	return nil
}

// unparsable codes a credential file its parser refused. The parser's text
// describes the local file (a wrong pkcs12 password included), so the user
// sees it.
func unparsable(path string, err error) error {
	return errcode.New(errcode.ClientCertUnusable).With(errcode.Invalidf("%w", err), "parse "+path)
}

// resolveServerName returns the name used to verify the server certificate.
//
// An IP literal is kept as ServerName. crypto/tls refuses an empty
// ServerName, omits SNI for an IP (RFC 6066) and verifies it against the IP
// SANs.
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
