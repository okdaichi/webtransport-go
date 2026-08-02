package webtransport

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Dialer is a convenience client that dials a fresh QUIC connection for each
// WebTransport session. It is a thin wrapper around Transport, preserved for
// callers that upgrade from the pre-v0.12 Dialer API.
//
// Each Dial call opens (and, on session close, closes) its own QUIC connection.
// To pool multiple sessions on a single QUIC connection, use Transport.NewClientConn
// + ClientConn.Dial instead.
type Dialer struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection.
	// It must set the h3 ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	// ApplicationProtocols is a list of application protocols that can be negotiated,
	// see section 3.3 of https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15 for details.
	ApplicationProtocols []string

	// StreamReorderingTimeout is the time an incoming WebTransport stream that cannot
	// be associated with a session is buffered. Defaults to 5 seconds.
	StreamReorderingTimeout time.Duration

	initOnce sync.Once
	tr       *Transport
}

func (d *Dialer) init() *Transport {
	d.initOnce.Do(func() {
		d.tr = &Transport{
			TLSClientConfig:         d.TLSClientConfig,
			QUICConfig:              d.QUICConfig,
			ApplicationProtocols:    d.ApplicationProtocols,
			StreamReorderingTimeout: d.StreamReorderingTimeout,
		}
	})
	return d.tr
}

// Dial dials a new WebTransport session to the given URL on a fresh QUIC connection.
// The QUIC connection is closed when the returned session is closed.
func (d *Dialer) Dial(ctx context.Context, urlStr string, reqHdr http.Header) (*http.Response, *Session, error) {
	return d.init().Dial(ctx, urlStr, reqHdr)
}

// Close stops the Dialer from establishing new sessions. It does not close
// already-established sessions or externally-supplied QUIC connections.
func (d *Dialer) Close() error {
	if d.tr == nil {
		return nil
	}
	return d.tr.Close()
}
