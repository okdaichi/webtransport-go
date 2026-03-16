package webtransport

import (
	"context"
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

func (w *settingserOnlyResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *settingserOnlyResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

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

func (w *settingserFlusherResponseWriter) Flush() {
	w.flushed = true
}

func newUpgradeRequestWithoutConnContext() *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "https://localhost/webtransport", nil)
	req.Proto = protocolHeader
	return req
}

func newUpgradeRequestWithConnContext(hasSessionManager bool) *http.Request {
	req := newUpgradeRequestWithoutConnContext()
	connCtx := &serverQUICConn{Conn: &quic.Conn{}}
	if hasSessionManager {
		connCtx.sessionManager = &sessionManager{}
	}
	ctx := context.WithValue(req.Context(), serverQUICConnKey, connCtx)
	return req.WithContext(ctx)
}

func TestUpgraderErrorPaths(t *testing.T) {
	var u Upgrader

	t.Run("missing QUIC connection context", func(t *testing.T) {
		req := newUpgradeRequestWithoutConnContext()
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "webtransport: missing QUIC connection")
	})

	t.Run("missing Settingser", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		_, err := u.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "webtransport: response writer doesn't implement http3.Settingser")
	})

	t.Run("missing Flusher does not commit response", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		w := &settingserOnlyResponseWriter{}
		_, err := u.Upgrade(w, req)
		require.EqualError(t, err, "webtransport: response writer doesn't implement http.Flusher")
		require.Zero(t, w.statusCode)
	})

	t.Run("missing HTTPStreamer does not commit response", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(true)
		w := &settingserFlusherResponseWriter{}
		_, err := u.Upgrade(w, req)
		require.EqualError(t, err, "webtransport: response writer doesn't implement http3.HTTPStreamer")
		require.Zero(t, w.statusCode)
		require.False(t, w.flushed)
	})

	t.Run("missing session manager is actionable and does not commit response", func(t *testing.T) {
		req := newUpgradeRequestWithConnContext(false)
		w := &settingserFlusherResponseWriter{}
		_, err := u.Upgrade(w, req)
		require.EqualError(t, err, "webtransport: session manager unavailable (request context not initialized by webtransport.Server; use Server.Serve / ListenAndServe / ServeQUICConn)")
		require.Zero(t, w.statusCode)
		require.False(t, w.flushed)
	})
}
