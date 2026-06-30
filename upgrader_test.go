package webtransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type settingserOnlyResponseWriter struct {
	header     http.Header
	statusCode int
}

func (w *settingserOnlyResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *settingserOnlyResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *settingserOnlyResponseWriter) WriteHeader(statusCode int) { w.statusCode = statusCode }

func (w *settingserOnlyResponseWriter) ReceivedSettings() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (w *settingserOnlyResponseWriter) Settings() *http3.Settings {
	return &http3.Settings{EnableDatagrams: true}
}

type settingserFlusherResponseWriter struct {
	settingserOnlyResponseWriter
	flushed bool
}

func (w *settingserFlusherResponseWriter) Flush() { w.flushed = true }

func newUpgradeRequestWithoutConnContext() *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "https://localhost/webtransport", nil)
	req.Proto = protocolHeader
	return req
}

func newUpgradeRequestWithConnContext(hasSessionManager bool) *http.Request {
	req := newUpgradeRequestWithoutConnContext()
	connCtx := &serverConnContext{conn: &quic.Conn{}}
	if hasSessionManager {
		connCtx.sessionManager = &sessionManager{}
	}
	ctx := context.WithValue(req.Context(), serverConnContextKey, connCtx)
	return req.WithContext(ctx)
}

func TestUpgraderErrorPaths(t *testing.T) {
	var u Upgrader

	t.Run("rejects non-CONNECT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost/webtransport", nil)
		req.Proto = protocolHeader
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected CONNECT request")
	})

	t.Run("missing QUIC connection context", func(t *testing.T) {
		req := newUpgradeRequestWithoutConnContext()
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing QUIC connection")
	})

	t.Run("missing session manager", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(false)
		_, err := u.Upgrade(&settingserFlusherResponseWriter{}, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "session manager unavailable")
	})

	t.Run("missing Settingser", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Settingser")
	})

	t.Run("missing Flusher does not commit response", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		w := &settingserOnlyResponseWriter{}
		_, err := u.Upgrade(w, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Flusher")
		require.Zero(t, w.statusCode)
	})

	t.Run("missing HTTPStreamer does not commit response", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		w := &settingserFlusherResponseWriter{}
		_, err := u.Upgrade(w, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "HTTPStreamer")
		require.Zero(t, w.statusCode)
		require.False(t, w.flushed)
	})
}

func TestUpgraderCheckOrigin(t *testing.T) {
	t.Run("default rejects cross-origin", func(t *testing.T) {
		var u Upgrader
		req := newUpgradeRequestWithConnContext(true)
		req.Header.Set("Origin", "https://evil.example")
		req.Host = "localhost"
		_, err := u.Upgrade(&settingserFlusherResponseWriter{}, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "origin not allowed")
	})

	t.Run("custom CheckOrigin is consulted", func(t *testing.T) {
		called := false
		u := Upgrader{CheckOrigin: func(r *http.Request) bool { called = true; return false }}
		req := newUpgradeRequestWithConnContext(true)
		_, err := u.Upgrade(&settingserFlusherResponseWriter{}, req)
		require.Error(t, err)
		require.True(t, called)
	})
}

func TestUpgraderSelectProtocol(t *testing.T) {
	u := Upgrader{ApplicationProtocols: []string{"myproto", "other"}}
	require.Equal(t, "myproto", u.selectProtocol([]string{`"myproto"`, `"other"`}))
	require.Equal(t, "other", u.selectProtocol([]string{`"other"`}))
	require.Empty(t, u.selectProtocol([]string{`"unknown"`}))
	require.Empty(t, u.selectProtocol([]string{`malformed`}))
}

// TestUpgraderHandshakeErrorType guards the gorilla-style contract: client-caused
// handshake failures are returned as HandshakeError (callers can errors.As them, e.g. to
// map to a 4xx), while server-side misconfiguration is returned as a plain error.
func TestUpgraderHandshakeErrorType(t *testing.T) {
	var u Upgrader

	isHandshake := func(t *testing.T, err error) {
		t.Helper()
		var he HandshakeError
		require.ErrorAs(t, err, &he, "expected a HandshakeError")
	}
	isNotHandshake := func(t *testing.T, err error) {
		t.Helper()
		var he HandshakeError
		require.False(t, errors.As(err, &he), "expected a plain (non-Handshake) error")
	}

	t.Run("wrong method is a handshake error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost/webtransport", nil)
		req.Proto = protocolHeader
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		isHandshake(t, err)
	})

	t.Run("wrong protocol is a handshake error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodConnect, "https://localhost/webtransport", nil)
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		isHandshake(t, err)
	})

	t.Run("rejected origin is a handshake error", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		req.Header.Set("Origin", "https://evil.example")
		req.Host = "localhost"
		_, err := u.Upgrade(&settingserFlusherResponseWriter{}, req)
		isHandshake(t, err)
	})

	t.Run("missing QUIC connection is NOT a handshake error", func(t *testing.T) {
		req := newUpgradeRequestWithoutConnContext()
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		isNotHandshake(t, err)
	})

	t.Run("missing session manager is NOT a handshake error", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(false)
		_, err := u.Upgrade(&settingserFlusherResponseWriter{}, req)
		isNotHandshake(t, err)
	})
}
