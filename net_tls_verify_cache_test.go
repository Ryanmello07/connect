package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

type testTlsChain struct {
	roots *x509.CertPool
	leaf  tls.Certificate
	certs []*x509.Certificate
}

// A root, an intermediate and a leaf for serverName, valid until notAfter.
func newTestTlsChain(t *testing.T, serverName string, notAfter time.Time) *testTlsChain {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	notBefore := time.Now().Add(-time.Hour)
	issue := func(template *x509.Certificate, parent *x509.Certificate, key *ecdsa.PrivateKey, parentKey *ecdsa.PrivateKey) *x509.Certificate {
		if parent == nil {
			parent = template
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootKey, intermediateKey, leafKey := newKey(), newKey(), newKey()
	root := issue(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, rootKey, rootKey)
	intermediate := issue(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, intermediateKey, rootKey)
	leaf := issue(&x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, leafKey, intermediateKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &testTlsChain{
		roots: roots,
		leaf: tls.Certificate{
			Certificate: [][]byte{leaf.Raw, intermediate.Raw},
			PrivateKey:  leafKey,
			Leaf:        leaf,
		},
		certs: []*x509.Certificate{leaf, intermediate},
	}
}

func TestTlsVerifiedChainCacheVerifiesOnceAndOnlyThatChain(t *testing.T) {
	cache := &tlsVerifiedChainCache{entries: map[[32]byte]time.Time{}}
	chain := newTestTlsChain(t, "api.cache.example", time.Now().Add(30*24*time.Hour))
	now := time.Now()

	count := tlsChainVerifyCount.Load()
	for range 3 {
		if err := cache.verify("api.cache.example", chain.roots, chain.certs, now); err != nil {
			t.Fatal(err)
		}
	}
	if verifies := tlsChainVerifyCount.Load() - count; verifies != 1 {
		t.Fatalf("verified %d times, want once", verifies)
	}

	// another name is its own entry, and fails on its own
	var verifyErr *tls.CertificateVerificationError
	if err := cache.verify("other.cache.example", chain.roots, chain.certs, now); !errors.As(err, &verifyErr) {
		t.Fatalf("a chain for another name verified: %v", err)
	}
	// a chain the roots do not sign never verifies, cached or not
	other := newTestTlsChain(t, "api.cache.example", time.Now().Add(30*24*time.Hour))
	if err := cache.verify("api.cache.example", chain.roots, other.certs, now); !errors.As(err, &verifyErr) {
		t.Fatalf("an unsigned chain verified: %v", err)
	}
	// the leaf alone, without the intermediate, is another chain
	if err := cache.verify("api.cache.example", chain.roots, chain.certs[:1], now); !errors.As(err, &verifyErr) {
		t.Fatalf("a leaf without its intermediate verified: %v", err)
	}
	if err := cache.verify("api.cache.example", chain.roots, nil, now); !errors.As(err, &verifyErr) {
		t.Fatalf("no certificate verified: %v", err)
	}

	// after the ttl the chain is verified again
	count = tlsChainVerifyCount.Load()
	if err := cache.verify("api.cache.example", chain.roots, chain.certs, now.Add(tlsVerifiedChainTtl)); err != nil {
		t.Fatal(err)
	}
	if verifies := tlsChainVerifyCount.Load() - count; verifies != 1 {
		t.Fatalf("verified %d times after the ttl, want once", verifies)
	}
}

// An entry never outlives the chain: a leaf that expires before the ttl is
// verified again, and refused, once it has expired.
func TestTlsVerifiedChainCacheEndsAtTheChainExpiry(t *testing.T) {
	cache := &tlsVerifiedChainCache{entries: map[[32]byte]time.Time{}}
	notAfter := time.Now().Add(10 * time.Minute)
	chain := newTestTlsChain(t, "api.cache.example", notAfter)
	if err := cache.verify("api.cache.example", chain.roots, chain.certs, time.Now()); err != nil {
		t.Fatal(err)
	}
	var verifyErr *tls.CertificateVerificationError
	if err := cache.verify("api.cache.example", chain.roots, chain.certs, notAfter.Add(time.Second)); !errors.As(err, &verifyErr) {
		t.Fatalf("an expired chain verified from the cache: %v", err)
	}
}

func TestTlsVerifiedChainCacheIsBounded(t *testing.T) {
	cache := &tlsVerifiedChainCache{entries: map[[32]byte]time.Time{}}
	now := time.Now()
	for i := range tlsVerifiedChainCacheCapacity + 10 {
		var key [32]byte
		key[0], key[1] = byte(i), byte(i>>8)
		cache.add(key, now.Add(time.Hour), now)
	}
	if n := len(cache.entries); tlsVerifiedChainCacheCapacity < n {
		t.Fatalf("cache holds %d entries, capacity %d", n, tlsVerifiedChainCacheCapacity)
	}
}

// Only plain verification against the cache's roots is replaced.
func TestWithCachedChainVerificationKeepsOtherConfigs(t *testing.T) {
	roots := x509.NewCertPool()
	base := &tls.Config{RootCAs: roots, ServerName: "api.cache.example"}
	if config := withCachedChainVerification(base, roots); config == base || !config.InsecureSkipVerify || config.VerifyConnection == nil {
		t.Fatal("a plain config was not given the cached verification")
	}
	if base.InsecureSkipVerify || base.VerifyConnection != nil {
		t.Fatal("the caller's config was changed")
	}
	verifier := func([][]byte, [][]*x509.Certificate) error { return nil }
	for name, config := range map[string]*tls.Config{
		"other roots":   {RootCAs: x509.NewCertPool(), ServerName: "api.cache.example"},
		"system roots":  {ServerName: "api.cache.example"},
		"no name":       {RootCAs: roots},
		"insecure":      {RootCAs: roots, ServerName: "api.cache.example", InsecureSkipVerify: true},
		"peer verifier": {RootCAs: roots, ServerName: "api.cache.example", VerifyPeerCertificate: verifier},
		"conn verifier": {RootCAs: roots, ServerName: "api.cache.example", VerifyConnection: func(tls.ConnectionState) error { return nil }},
		"fixed clock":   {RootCAs: roots, ServerName: "api.cache.example", Time: time.Now},
	} {
		if withCachedChainVerification(config, roots) != config {
			t.Fatalf("%s: the config was replaced", name)
		}
	}
}

// End to end through crypto/tls: a cached handshake still refuses a server
// that presents a chain it has no key for.
func TestWithCachedChainVerificationHandshake(t *testing.T) {
	chain := newTestTlsChain(t, "api.cache.example", time.Now().Add(30*24*time.Hour))
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{chain.leaf}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	dial := func(serverName string) error {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return err
		}
		defer conn.Close()
		config := withCachedChainVerification(&tls.Config{RootCAs: chain.roots, ServerName: serverName}, chain.roots)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return tls.Client(conn, config).HandshakeContext(ctx)
	}
	count := tlsChainVerifyCount.Load()
	for range 3 {
		if err := dial("api.cache.example"); err != nil {
			t.Fatal(err)
		}
	}
	if verifies := tlsChainVerifyCount.Load() - count; verifies != 1 {
		t.Fatalf("verified %d times over three handshakes, want once", verifies)
	}
	var verifyErr *tls.CertificateVerificationError
	if err := dial("other.cache.example"); !errors.As(err, &verifyErr) {
		t.Fatalf("a handshake for another name succeeded: %v", err)
	}

	// a server replaying the cached chain without its key fails the handshake
	impostor := newTestTlsChain(t, "api.cache.example", time.Now().Add(30*24*time.Hour))
	replayed := chain.leaf
	replayed.PrivateKey = impostor.leaf.PrivateKey
	impostorListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{replayed}})
	if err != nil {
		t.Fatal(err)
	}
	defer impostorListener.Close()
	go func() {
		conn, err := impostorListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.(*tls.Conn).Handshake()
	}()
	conn, err := net.Dial("tcp", impostorListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	config := withCachedChainVerification(&tls.Config{RootCAs: chain.roots, ServerName: "api.cache.example"}, chain.roots)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tls.Client(conn, config).HandshakeContext(ctx); err == nil {
		t.Fatal("a server without the leaf key completed a handshake on the cached chain")
	}
}
