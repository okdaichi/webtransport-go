package webtransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/dunglas/httpsfv"
)

// Upgrader upgrades a single HTTP/3 request to a WebTransport session.
//
// Configure an Upgrader with the application's origin policy, negotiable application
// protocols, and SETTINGS wait, then call Upgrade from the http.Handler that the
// Server's H3.Server dispatches to. Upgrader is safe for concurrent use.
//
// Upgrade requires the request to have been routed through a webtransport.Server
// (Serve / ListenAndServe / ServeQUICConn): the Server provisions the underlying QUIC
// connection and the per-connection stream router via the request context, and Upgrade
// reads them from there. Calling Upgrade on a request that did not come from a
// webtransport.Server returns an error. This mirrors the standard library pattern used
// by http.Hijacker / websocket.Upgrader, where the upgrade is only meaningful inside a
// serving context.
type Upgrader struct {
	// ApplicationProtocols is a list of application protocols that can be negotiated,
	// see section 3.3 of https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15 for details.
	ApplicationProtocols []string

	// ReorderingTimeout is the maximum time Upgrade blocks waiting for the client's
	// SETTINGS to be received after the CONNECT request. Defaults to 5 seconds.
	// (Buffering of streams that arrive before a session's CONNECT is a separate,
	// connection-level concern handled by the Server and is not governed by this value.)
	ReorderingTimeout time.Duration

	// CheckOrigin is used to validate the request origin, thereby preventing cross-site request forgery.
	// CheckOrigin returns true if the request Origin header is acceptable.
	// If unset, a safe default is used: If the Origin header is set, it is checked that it
	// matches the request's Host header.
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
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Session, error) {
	if r.Method != http.MethodConnect {
		return nil, fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if !isWebTransportProtocol(r.Proto) {
		return nil, fmt.Errorf("unexpected protocol: %s", r.Proto)
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return nil, errors.New("webtransport: request origin not allowed")
	}

	connCtx := serverConnContextFromRequest(r)
	if connCtx == nil || connCtx.conn == nil {
		return nil, errors.New("webtransport: missing QUIC connection (request was not routed through a webtransport.Server)")
	}
	if connCtx.sessionManager == nil {
		return nil, errors.New("webtransport: session manager unavailable (request was not routed through a webtransport.Server)")
	}

	selectedProtocol := u.selectProtocol(r.Header[http.CanonicalHeaderKey(wtAvailableProtocolsHeader)])

	// Wait for the client's SETTINGS.
	settingser, ok := w.(http3.Settingser)
	if !ok {
		return nil, errors.New("webtransport: response writer doesn't implement http3.Settingser")
	}
	timer := time.NewTimer(u.timeout())
	defer timer.Stop()
	select {
	case <-settingser.ReceivedSettings():
	case <-timer.C:
		return nil, errors.New("webtransport: didn't receive the client's SETTINGS on time")
	}
	if !settingser.Settings().EnableDatagrams {
		return nil, errors.New("webtransport: missing datagram support")
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

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	str := httpStreamer.HTTPStream()
	sessID := sessionID(str.StreamID())

	sess := newSession(context.WithoutCancel(r.Context()), sessID, connCtx.conn, str, selectedProtocol)
	connCtx.sessionManager.AddSession(sessID, sess)
	return sess, nil
}
