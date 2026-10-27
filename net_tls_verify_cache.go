package connect

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// A process that runs many clients (one provider per proxy) dials the same
// few platform hosts over and over, and every full handshake re-verifies the
// same certificate chain against the pinned roots: two P-384 signature checks
// per dial, which was a quarter to a third of such a process's cpu.
//
// The cache remembers only that one exact chain, presented for one server
// name, verified against the shared pinned pool, until the earlier of
// `tlsVerifiedChainTtl` and the first expiry in that chain. It holds no
// session state and changes nothing on the wire: each dial path keeps its own
// ticket cache (`newClientTlsConfig`), and the handshake still checks the
// server's signature with the leaf key, so a cached chain proves nothing to a
// peer that does not hold that key.
const tlsVerifiedChainTtl = time.Hour

const tlsVerifiedChainCacheCapacity = 1024

type tlsVerifiedChainCache struct {
	mutex sync.Mutex
	// chain key -> verified until
	entries map[[32]byte]time.Time
}

var defaultTlsVerifiedChainCache = &tlsVerifiedChainCache{
	entries: map[[32]byte]time.Time{},
}

// counts full chain verifications, for tests
var tlsChainVerifyCount atomic.Uint64

func (self *tlsVerifiedChainCache) verified(key [32]byte, now time.Time) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	until, ok := self.entries[key]
	if !ok {
		return false
	}
	if !now.Before(until) {
		delete(self.entries, key)
		return false
	}
	return true
}

func (self *tlsVerifiedChainCache) add(key [32]byte, until time.Time, now time.Time) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if tlsVerifiedChainCacheCapacity <= len(self.entries) {
		for entryKey, entryUntil := range self.entries {
			if !now.Before(entryUntil) {
				delete(self.entries, entryKey)
			}
		}
		if tlsVerifiedChainCacheCapacity <= len(self.entries) {
			clear(self.entries)
		}
	}
	self.entries[key] = until
}

func tlsVerifiedChainKey(serverName string, certs []*x509.Certificate) [32]byte {
	h := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(serverName)))
	h.Write(length[:])
	h.Write([]byte(serverName))
	for _, cert := range certs {
		binary.BigEndian.PutUint64(length[:], uint64(len(cert.Raw)))
		h.Write(length[:])
		h.Write(cert.Raw)
	}
	var key [32]byte
	h.Sum(key[:0])
	return key
}

// Verifies certs for serverName against roots as crypto/tls's own client
// verification does (server auth usage, the name or ip in the leaf, the
// presented intermediates), consulting and filling the cache.
func (self *tlsVerifiedChainCache) verify(
	serverName string,
	roots *x509.CertPool,
	certs []*x509.Certificate,
	now time.Time,
) error {
	if len(certs) == 0 {
		return &tls.CertificateVerificationError{Err: errors.New("tls: server presented no certificate")}
	}
	key := tlsVerifiedChainKey(serverName, certs)
	if self.verified(key, now) {
		return nil
	}
	tlsChainVerifyCount.Add(1)
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		CurrentTime:   now,
	})
	if err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	until := now.Add(tlsVerifiedChainTtl)
	for _, cert := range chains[0] {
		if cert.NotAfter.Before(until) {
			until = cert.NotAfter
		}
	}
	self.add(key, until, now)
	return nil
}

// Returns config, or a clone of it that verifies the server's chain through
// the cache. Only a configuration that would get crypto/tls's plain
// verification against `cacheRoots` is changed: any other roots, a caller's
// own verifier, a fixed clock, or no server name keep crypto/tls's path.
func withCachedChainVerification(config *tls.Config, cacheRoots *x509.CertPool) *tls.Config {
	if config == nil ||
		cacheRoots == nil ||
		config.RootCAs != cacheRoots ||
		config.InsecureSkipVerify ||
		config.VerifyPeerCertificate != nil ||
		config.VerifyConnection != nil ||
		config.Time != nil ||
		config.ServerName == "" {
		return config
	}
	serverName := config.ServerName
	cachedConfig := config.Clone()
	// the chain is verified below instead; crypto/tls still verifies the
	// server's handshake signature with the leaf key
	cachedConfig.InsecureSkipVerify = true
	cachedConfig.VerifyConnection = func(state tls.ConnectionState) error {
		return defaultTlsVerifiedChainCache.verify(serverName, cacheRoots, state.PeerCertificates, time.Now())
	}
	return cachedConfig
}

// The shared pinned pool, the one the cache applies to; nil if the embedded
// roots do not parse.
func tlsVerifiedChainCacheRoots() *x509.CertPool {
	roots, err := sharedDefaultPinnedCertPool()
	if err != nil {
		return nil
	}
	return roots
}
