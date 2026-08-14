package extender

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"testing"

	"github.com/urnetwork/connect"
)

func TestExtender(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	// actual content server, port 443 (127.0.0.1)
	// https, self signed
	// one route, /hello

	// extender server, port 442

	// client

	// test uses extender http client to GET /hello

	settings := DefaultExtenderSettings()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certPemBytes, keyPemBytes, err := selfSign([]string{"localhost"}, "Connect Test", settings.ValidFrom, settings.ValidFor)
	connect.AssertEqual(t, err, nil)

	tempDirPath := t.TempDir()

	certFile := filepath.Join(tempDirPath, "localhost.pem")
	keyFile := filepath.Join(tempDirPath, "localhost.key")
	connect.AssertEqual(t, os.WriteFile(certFile, certPemBytes, 0o600), nil)
	connect.AssertEqual(t, os.WriteFile(keyFile, keyPemBytes, 0o600), nil)

	// the ports are shared between the servers, the client and the readiness poll
	// below, so that the poll cannot drift from what actually gets listened on
	const contentPort = 443
	const extenderPort = 1442

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", contentPort),
		Handler: &testExtenderServer{},
	}
	defer server.Close()
	go server.ListenAndServeTLS(certFile, keyFile)

	extenderServer := NewExtenderServer(
		ctx,
		[]string{"montrose"},
		[]string{"localhost"},
		map[int][]connect.ExtenderConnectMode{
			extenderPort: []connect.ExtenderConnectMode{connect.ExtenderConnectModeTcpTls},
		},
		&net.Dialer{},
		settings,
	)
	defer extenderServer.Close()
	go extenderServer.ListenAndServe()

	// both listeners bind on a goroutine, so wait until each one actually accepts
	// before issuing the request. a fixed sleep here is a race: on a loaded runner
	// the bind can land after the sleep expires and the request then fails with
	// EOF, which is what talking to a not-yet-listening socket looks like.
	awaitListening(
		t,
		fmt.Sprintf("127.0.0.1:%d", contentPort),
		fmt.Sprintf("127.0.0.1:%d", extenderPort),
	)

	localIp, err := netip.ParseAddr("127.0.0.1")
	connect.AssertEqual(t, err, nil)

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPemBytes) {
		t.Fatal("could not add content server certificate")
	}
	connectSettings := connect.DefaultConnectSettings()
	connectSettings.TlsConfig = &tls.Config{
		RootCAs: rootCAs,
	}

	client := connect.NewExtenderHttpClient(
		connectSettings,
		&connect.ExtenderConfig{
			Profile: connect.ExtenderProfile{
				ConnectMode: connect.ExtenderConnectModeTcpTls,
				ServerName:  "bringyour.com",
				Port:        1442,
			},
			Ip:     localIp,
			Secret: "montrose",
		},
	)

	r, err := client.Get("https://localhost/hello")

	connect.AssertEqual(t, err, nil)
	connect.AssertEqual(t, r.StatusCode, 200)

	body, err := io.ReadAll(r.Body)
	connect.AssertEqual(t, err, nil)
	connect.AssertEqual(t, string(body), "{}")

}

// awaitListening blocks until every addr accepts a tcp connection, and fails the
// test if any of them is still not accepting when the overall deadline passes.
func awaitListening(t *testing.T, addrs ...string) {
	t.Helper()

	const timeout = 5 * time.Second
	const pollInterval = 10 * time.Millisecond

	deadline := time.Now().Add(timeout)
	for _, addr := range addrs {
		for {
			conn, err := net.DialTimeout("tcp", addr, pollInterval*10)
			if err == nil {
				conn.Close()
				break
			}
			if !time.Now().Before(deadline) {
				t.Fatalf("%s was not accepting connections within %s: %s", addr, timeout, err)
			}
			select {
			case <-time.After(pollInterval):
			}
		}
	}
}

func TestSelfSignValiditySpansPresent(t *testing.T) {
	before := time.Now()
	certPemBytes, _, err := selfSign(
		[]string{"localhost"},
		"Connect Test",
		2*time.Hour,
		3*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPemBytes)
	if block == nil {
		t.Fatal("selfSign returned no certificate PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	if delta := certificate.NotBefore.Sub(before.Add(-2 * time.Hour)); delta < -time.Second || time.Second < delta {
		t.Fatalf("NotBefore = %s, expected about two hours before creation", certificate.NotBefore)
	}
	if delta := certificate.NotAfter.Sub(after.Add(3 * time.Hour)); delta < -time.Second || time.Second < delta {
		t.Fatalf("NotAfter = %s, expected about three hours after creation", certificate.NotAfter)
	}
	if before.Before(certificate.NotBefore) || certificate.NotAfter.Before(after) {
		t.Fatalf("certificate validity %s..%s does not span creation", certificate.NotBefore, certificate.NotAfter)
	}
}

type testExtenderServer struct {
}

func (self *testExtenderServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte("{}"))
}
