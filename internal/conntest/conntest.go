// Package conntest drives a schedd command handler over an in-memory CEDAR
// connection in tests: the handler gets a cedarserver.Conn carrying a chosen
// security negotiation, and the test speaks the wire protocol on the other end.
package conntest

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Logger returns a logger writing to a file in the test's temp dir.
func Logger(t testing.TB) *logging.Logger {
	t.Helper()
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return log
}

// Negotiation returns a completed security negotiation whose User is user and
// whose Authentication flag is authenticated.
func Negotiation(user string, authenticated bool) *security.SecurityNegotiation {
	return &security.SecurityNegotiation{User: user, Authentication: authenticated}
}

// Serve runs handler on a server-side Conn for command cmd with negotiation neg
// and returns the client end of the connection plus a channel that receives the
// handler's result when it returns. Both ends are closed at test cleanup, and a
// deadline keeps a protocol mismatch from hanging the test.
func Serve(t testing.TB, cmd int, neg *security.SecurityNegotiation,
	handler func(context.Context, *cedarserver.Conn) error) (*stream.Stream, <-chan error) {
	t.Helper()
	srvEnd, cliEnd := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	_ = srvEnd.SetDeadline(deadline)
	_ = cliEnd.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = cliEnd.Close()
		_ = srvEnd.Close()
	})
	conn := &cedarserver.Conn{Stream: stream.NewStream(srvEnd), Command: cmd, Negotiation: neg}
	done := make(chan error, 1)
	go func() { done <- handler(context.Background(), conn) }()
	return stream.NewStream(cliEnd), done
}
