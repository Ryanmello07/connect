package connect

import (
	"context"
	"net"
)

// dialControlTlsWithFamilyFallback performs a control-plane dial and its
// handshake, and retries ONCE over the other address family when the handshake
// fails with a timeout after the connect succeeded.
//
// That sequence -- connect succeeds, handshake times out -- is the signature of
// a path that carries small packets and drops large ones, which is what a
// tunnel with a reduced MTU and filtered ICMP Packet-Too-Big does. Happy
// Eyeballs cannot see it: it races only the tcp handshake, so the broken family
// WINS the race and then stalls.
//
// Exactly one retry, and only to the other family. The caller already sits
// inside the client strategy's serial and parallel dialer evaluation under a
// shared request budget, so a helper that retried repeatedly could consume the
// whole budget alone and starve the other dialers -- which is the failure this
// exists to prevent, not to reproduce. A second failure over the second family
// is also not a family problem, and the original error is returned unwrapped.
func dialControlTlsWithFamilyFallback(
	ctx context.Context,
	network string,
	addr string,
	dial DialContextFunction,
	handshake func(ctx context.Context, conn net.Conn) (net.Conn, error),
) (net.Conn, error) {
	conn, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// BEFORE the handshake, and before any Close: a closed net.TCPConn is not
	// required to keep answering RemoteAddr, and the family of the connection
	// we are about to lose is the whole point of the exercise.
	failed := connFamily(conn)

	tlsConn, err := handshake(ctx, conn)
	if err == nil {
		return tlsConn, nil
	}
	conn.Close()

	// only a family-agnostic dial has somewhere else to go
	if network != "tcp" && network != "udp" {
		return nil, err
	}
	if !isPathTimeout(err) {
		return nil, err
	}
	if failed == 0 {
		return nil, err
	}
	if !controlFamilyDemote(failed) {
		// refused: the other family is not usable on this device, so there is
		// nothing to retry onto
		return nil, err
	}

	retryNetwork := network + "4"
	if failed == 4 {
		retryNetwork = network + "6"
	}
	retryConn, retryErr := dial(ctx, retryNetwork, addr)
	if retryErr != nil {
		return nil, err
	}
	retryTlsConn, retryErr := handshake(ctx, retryConn)
	if retryErr != nil {
		retryConn.Close()
		return nil, err
	}
	return retryTlsConn, nil
}
