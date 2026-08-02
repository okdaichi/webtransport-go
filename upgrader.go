package webtransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/dunglas/httpsfv"
)

// HandshakeError describes an error with the WebTransport handshake from the peer.
// Upgrade returns a HandshakeError for client-caused handshake failures — wrong request
// method or :protocol, a rejected origin, the client's SETTINGS not arriving in time, or
// missing datagram support. Server-side misconfiguration (the request was not routed
// through a webtransport.Server, or the ResponseWriter lacks required http3 interfaces)
// is returned as a plain error instead.
//
// Callers can distinguish the two with errors.As:
//
//	var he webtransport.HandshakeError
//	if errors.As(err, &he) { /* client-side handshake failure */ }
type HandshakeError struct {
	message string
}

func (e HandshakeError) Error() string { return e.message }

// handshakeError returns a HandshakeError carrying the formatted message.
func handshakeError(format string, a ...any) error {
	return HandshakeError{message: fmt.Sprintf(format, a...)}
}

// serverConnContext carries everything Upgrader.Upgrade needs from the Server that
// routed the request: the underlying QUIC connection, the per-connection stream router
// (session manager), and the resolved WebTransport Config (for flow-control negotiation).
// It is stamped onto the request context by Server's ConnContext hook, so an Upgrader
// (which has no back-reference to a Server) can complete a handshake.
type serverConnContext struct {
	conn           *quic.Conn
	sessionManager *sessionManager
	config         Config
}

type serverConnContextKeyType struct{}

var serverConnContextKey = serverConnContextKeyType{}

func serverConnContextFromRequest(r *http.Request) *serverConnContext {
	v, _ := r.Context().Value(serverConnContextKey).(*serverConnContext)
	return v
}

// Upgrader upgrades a single HTTP/3 request to a WebTransport session.
//
// Configure an Upgrader with the application's origin policy, negotiable application
// protocols, and SETTINGS wait, then call Upgrade from the http.Handler that the
// Server's H3.Server dispatches to. It is safe to call an Upgrader's methods concurrently.
//
// Upgrade requires the request to have been routed through a webtransport.Server
// (Serve / ListenAndServe / ServeQUICConn): the Server provisions the underlying QUIC
// connection, the per-connection stream router, and the WebTransport flow-control
// configuration via the request context, and Upgrade reads them from there. Calling
// Upgrade on a request that did not come from a webtransport.Server returns an error.
// This mirrors the standard library pattern used by http.Hijacker / websocket.Upgrader,
// where the upgrade is only meaningful inside a serving context.
type Upgrader struct {
	// ApplicationProtocols is a list of application protocols that can be negotiated,
	// see section 3.3 of https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15 for details.
	ApplicationProtocols []string

	// ReorderingTimeout is the maximum time Upgrade blocks waiting for the client's
	// SETTINGS to be received after the CONNECT request. Defaults to 5 seconds.
	// (Buffering of streams that arrive before a session's CONNECT is a separate,
	// connection-level concern handled by the Server and is not governed by this value.)
	ReorderingTimeout time.Duration

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, then a safe default is used: return false if the Origin
	// request header is present and the origin host is not equal to the request Host
	// header.
	//
	// A CheckOrigin function should carefully validate the request origin to prevent
	// cross-site request forgery.
	CheckOrigin func(r *http.Request) bool
}

func (u *Upgrader) timeout() time.Duration {
	if u.ReorderingTimeout > 0 {
		return u.ReorderingTimeout
	}
	return 5 * time.Second
}

func (u *Upgrader) selectProtocol(theirs []string) string {
	list, err := httpsfv.UnmarshalList(theirs)
	if err != nil {
		return ""
	}
	offered := make([]string, 0, len(list))
	for _, item := range list {
		i, ok := item.(httpsfv.Item)
		if !ok {
			return ""
		}
		protocol, ok := i.Value.(string)
		if !ok {
			return ""
		}
		offered = append(offered, protocol)
	}
	for _, p := range offered {
		if slices.Contains(u.ApplicationProtocols, p) {
			return p
		}
	}
	return ""
}

// Upgrade upgrades the incoming HTTP/3 request to a WebTransport session.
// The request must have been routed through a webtransport.Server.
//
// A client-caused handshake failure is returned as a HandshakeError; other failures
// (the request was not routed through a webtransport.Server, or the ResponseWriter is
// missing required http3 interfaces) are returned as a plain error. Upgrade does not
// write an HTTP error response on failure; the caller is responsible for replying.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Session, error) {
	if r.Method != http.MethodConnect {
		return nil, handshakeError("expected CONNECT request, got %s", r.Method)
	}
	if !isWebTransportProtocol(r.Proto) {
		return nil, handshakeError("unexpected protocol: %s", r.Proto)
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return nil, handshakeError("webtransport: request origin not allowed")
	}

	connCtx := serverConnContextFromRequest(r)
	if connCtx == nil || connCtx.conn == nil {
		return nil, errors.New("webtransport: missing QUIC connection (request was not routed through a webtransport.Server)")
	}
	if connCtx.sessionManager == nil {
		return nil, errors.New("webtransport: session manager unavailable (request was not routed through a webtransport.Server)")
	}
	conn := connCtx.conn
	sessMgr := connCtx.sessionManager

	selectedProtocol := u.selectProtocol(r.Header[http.CanonicalHeaderKey(wtAvailableProtocolsHeader)])

	// Wait for the client's SETTINGS, but give up if the connection closes first.
	settingser, ok := w.(http3.Settingser)
	if !ok {
		return nil, errors.New("webtransport: response writer doesn't implement http3.Settingser")
	}
	timer := time.NewTimer(u.timeout())
	defer timer.Stop()
	select {
	case <-settingser.ReceivedSettings():
	case <-timer.C:
		return nil, handshakeError("webtransport: didn't receive the client's SETTINGS on time")
	}
	settings := settingser.Settings()
	if !settings.EnableDatagrams {
		return nil, handshakeError("webtransport: missing datagram support")
	}

	if selectedProtocol != "" {
		v, err := httpsfv.Marshal(httpsfv.NewItem(selectedProtocol))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal selected protocol: %w", err)
		}
		w.Header().Set(wtProtocolHeader, v)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("webtransport: response writer doesn't implement http.Flusher")
	}
	httpStreamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("webtransport: response writer doesn't implement http3.HTTPStreamer")
	}

	str := httpStreamer.HTTPStream()
	sessID := sessionID(str.StreamID())
	fc := connCtx.config.sessionFlowControl(settings)

	// Multiple sessions on one HTTP/3 connection require WebTransport flow control.
	if !fc.Enabled {
		sessMgr.mx.Lock()
		for _, entry := range sessMgr.sessions {
			if entry.Session != nil {
				sessMgr.mx.Unlock()
				str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
				str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
				return nil, errors.New("webtransport: multiple sessions require flow control")
			}
		}
		sessMgr.mx.Unlock()
	}

	sess := newSession(
		context.WithoutCancel(r.Context()),
		sessID,
		conn,
		str,
		selectedProtocol,
		fc,
	)
	sessMgr.AddSession(sessID, sess)

	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return sess, nil
}
