package site

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type observedListener struct {
	net.Listener
	accepted chan struct{}
}

func (l observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		close(l.accepted)
	}
	return conn, err
}

func TestGeminiDrainsAcceptedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeGemini(ctx, observedListener{ln, accepted}) }()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	<-accepted
	cancel()
	select {
	case err := <-done:
		t.Fatalf("accepted connection abandoned: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := conn.Write([]byte("gemini://fixture/missing\r\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "51 ") {
		t.Fatalf("missing completed Gemini response: %q %v", line, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRequiredGeminiTLSNeverFallsBack(t *testing.T) {
	t.Setenv("KITTY_REQUIRE_TLS", "true")
	t.Setenv("KITTY_GEMINI_ADDR", "127.0.0.1:0")
	t.Setenv("KITTY_GEMINI_CERT", filepath.Join(t.TempDir(), "absent.pem"))
	for _, plaintext := range []string{"", "1"} {
		t.Setenv("GEMINI_PLAINTEXT", plaintext)
		if ln, err := NewGeminiListener(); err == nil {
			ln.Close()
			t.Fatal("TLS required but plaintext listener was opened")
		}
	}
}
