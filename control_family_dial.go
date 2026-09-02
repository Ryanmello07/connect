package connect

import (
	"context"
	"net"
	"time"
)

// controlFamilyMinHandshakeBudget is the least time the first handshake may be
// held to before its timeout stops being evidence about the path. A tls
// handshake is one to two round trips on top of the connect, and a congested
// mobile link can spend a second on those, so an attempt cut below a couple of
// seconds would call a slow link a broken one. When the caller cannot afford
// this much for the first attempt AND as much again for a retry, the helper
// does not divide the budget at all and does not demote: there would be
// nothing left to act on, and a request that merely ran out of time proves
// nothing.
const controlFamilyMinHandshakeBudget = 2 * time.Second

// controlFamilyHandshakeBudget bounds the FIRST handshake to half of whatever
// the caller has left, so that one retry over the other family still fits
// inside the caller's own deadline. The failure this exists to catch is a
// handshake that stalls until its deadline -- a blackholed path gives up only
// when the context does, because the kernel retransmits for minutes -- so a
// first attempt allowed to spend the whole request budget hands the retry a
// context that is already dead.
//
// The third result reports whether the returned budget is the HANDSHAKE's own.
// It is false only when the caller's remaining time is too small to divide, in
// which case a timeout below is the request running out rather than the path
// failing. That distinction is what keeps a user on a genuinely slow link from
// having a healthy family demoted for five minutes.
func controlFamilyHandshakeBudget(
	ctx context.Context,
) (context.Context, context.CancelFunc, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// no budget to divide, and no caller deadline that could be mistaken
		// for the handshake's own
		return ctx, func() {}, true
	}
	half := time.Until(deadline) / 2
	if half < controlFamilyMinHandshakeBudget {
		return ctx, func() {}, false
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, half)
	return handshakeCtx, cancel, true
}

// dialControlTlsWithFamilyFallback performs a control-plane dial and its
// handshake, and retries ONCE over the other address family when the handshake
// fails with a timeout of its own after the connect succeeded.
//
// That sequence -- connect succeeds, handshake times out -- is the signature of
// a path that carries small packets and drops large ones, which is what a
// tunnel with a reduced MTU and filtered ICMP Packet-Too-Big does. Happy
// Eyeballs cannot see it: it races only the tcp handshake, so the broken family
// WINS the race and then stalls.
//
// The first handshake is held to half the caller's remaining budget so the
// retry has the other half to work in and the caller receives a working
// connection. A timeout that arrives with the caller's own budget already
// spent is NOT counted: that is a request running out of time, which says
// nothing about the family, and there would be no time to retry either way.
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

	handshakeCtx, cancelHandshake, handshakeOwnsBudget := controlFamilyHandshakeBudget(ctx)
	tlsConn, err := handshake(handshakeCtx, conn)
	cancelHandshake()
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
	// the timeout has to be the handshake's own. A caller whose budget is
	// gone gets no strike and no retry -- the strike records what this helper
	// is about to test, and it cannot test anything with no time left.
	if !handshakeOwnsBudget || ctx.Err() != nil {
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
