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

// Upgrader upgrades incoming HTTP requests to WebTransport sessions.
//
// It is safe to call Upgrader methods concurrently.
type Upgrader struct {
	// ApplicationProtocols is a list of application protocols that can be negotiated,
	// see section 3.3 of https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14 for details.
	ApplicationProtocols []string

	// ReorderingTimeout is the maximum time a WebTransport connection request is
	// blocked waiting for the client's SETTINGS to be received.
	// Defaults to 5 seconds.
	ReorderingTimeout time.Duration

	// CheckOrigin is used to validate the request origin, thereby preventing cross-site request forgery.
	// CheckOrigin returns true if the request Origin header is acceptable.
	// If unset, a safe default is used: If the Origin header is set, it is checked that it
	// matches the request's Host header.
	CheckOrigin func(r *http.Request) bool
}

func (u *Upgrader) timeout() time.Duration {
	timeout := u.ReorderingTimeout
	if timeout == 0 {
		return 5 * time.Second
	}
	return timeout
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
	var selectedProtocol string
	for _, p := range offered {
		if slices.Contains(u.ApplicationProtocols, p) {
			selectedProtocol = p
			break
		}
	}
	return selectedProtocol
}

// Upgrade upgrades an incoming HTTP request to a WebTransport session.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Session, error) {
	if r.Method != http.MethodConnect {
		return nil, fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if r.Proto != protocolHeader {
		return nil, fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return nil, errors.New("webtransport: request origin not allowed")
	}

	v := r.Context().Value(serverQUICConnKey)
	conn, ok := v.(*serverQUICConn)
	if !ok || conn == nil || conn.Conn == nil {
		return nil, errors.New("webtransport: missing QUIC connection")
	}
	if conn.sessionManager == nil {
		return nil, errors.New("webtransport: session manager unavailable (request context not initialized by webtransport.Server; use Server.Serve / ListenAndServe / ServeQUICConn)")
	}

	selectedProtocol := u.selectProtocol(r.Header[http.CanonicalHeaderKey(wtAvailableProtocolsHeader)])

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
	settings := settingser.Settings()
	if !settings.EnableDatagrams {
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
	str := httpStreamer.HTTPStream()
	sessID := sessionID(str.StreamID())

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sess := newSession(context.WithoutCancel(r.Context()), sessID, conn.Conn, str, selectedProtocol)
	conn.sessionManager.AddSession(sessID, sess)
	return sess, nil
}
