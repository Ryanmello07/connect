package connect

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// The cached verification through both hellos the handshaker presents.
func TestCachedChainVerificationThroughBothHellos(t *testing.T) {
	chain := newTestTlsChain(t, "api.cache.example", time.Now().Add(30*24*time.Hour))
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{chain.leaf}, NextProtos: []string{"h2", "http/1.1"}})
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
				time.Sleep(100 * time.Millisecond)
			}()
		}
	}()
	for _, fingerprint := range []string{TlsClientHelloFingerprintChrome, TlsClientHelloFingerprintGo} {
		base := newClientTlsConfig(&tls.Config{RootCAs: chain.roots}, clientHttpNextProtos)
		handshaker := newClientTlsHandshaker(fingerprint, base)
		t.Logf("%q chrome=%t", fingerprint, handshaker.chrome)
		for i := range 2 {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			config := base.Clone()
			config.ServerName = "api.cache.example"
			config = withCachedChainVerification(config, chain.roots)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			tlsConn, err := handshaker.handshake(ctx, conn, config)
			cancel()
			if err != nil {
				t.Fatalf("%s hello (chrome=%t) dial %d: %v", fingerprint, handshaker.chrome, i, err)
			}
			tlsConn.Close()
		}
	}
}
