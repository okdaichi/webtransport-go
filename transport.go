package webtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// A Transport configures WebTransport clients.
// Dial creates a new QUIC connection for each session. To establish multiple
// sessions on one QUIC connection, use NewClientConn.
type Transport struct {
	// Config is the WebTransport configuration used for new sessions.
	Config *Config

	// TLSClientConfig is the TLS client config used when dialing the QUIC connection.
	// It must set the h3 ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	// ApplicationProtocols is a list of application protocols that can be negotiated,
	// see section 3.3 of https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15 for details.
	ApplicationProtocols []string

	// StreamReorderingTime is the time an incoming WebTransport stream that cannot be associated
	// with a session is buffered.
	// This can happen if the response to a CONNECT request (that creates a new session) is reordered,
	// and arrives after the first WebTransport stream(s) for that session.
	// Defaults to 5 seconds.
	StreamReorderingTimeout time.Duration

	// DialAddr is the function used to dial the underlying QUIC connection.
	// If unset, quic.DialAddrEarly will be used.
	DialAddr func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)

	ctx       context.Context
	ctxCancel context.CancelFunc

	initOnce sync.Once
}

func (d *Transport) init() {
	d.ctx, d.ctxCancel = context.WithCancel(context.Background())
}

// Dial establishes a WebTransport session on a new QUIC connection.
// The QUIC connection is closed when the returned session is closed.
func (d *Transport) Dial(ctx context.Context, urlStr string, reqHdr http.Header) (*http.Response, *Session, error) {
	d.initOnce.Do(func() { d.init() })
	quicConf := d.QUICConfig
	if quicConf == nil {
		quicConf = &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		}
	} else {
		if !d.QUICConfig.EnableDatagrams {
			return nil, nil, errors.New("webtransport: DATAGRAM support required, enable it via QUICConfig.EnableDatagrams")
		}
		if !d.QUICConfig.EnableStreamResetPartialDelivery {
			return nil, nil, errors.New("webtransport: stream reset partial delivery required, enable it via QUICConfig.EnableStreamResetPartialDelivery")
		}
	}

	tlsConf := d.TLSClientConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{http3.NextProtoH3}
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}

	dialAddr := d.DialAddr
	if dialAddr == nil {
		dialAddr = quic.DialAddrEarly
	}
	qconn, err := dialAddr(ctx, u.Host, tlsConf, quicConf)
	if err != nil {
		return nil, nil, err
	}

	clientConn, err := d.NewClientConn(qconn)
	if err != nil {
		qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		return nil, nil, err
	}
	rsp, sess, err := clientConn.dial(ctx, u, reqHdr)
	if err != nil {
		var msg string
		code := quic.ApplicationErrorCode(http3.ErrCodeNoError)
		if reqErr, ok := errors.AsType[*RequirementsNotMetError](err); ok {
			code = WTRequirementsNotMetErrorCode
			msg = reqErr.Message
		}
		qconn.CloseWithError(code, msg)
		return rsp, nil, err
	}
	context.AfterFunc(sess.Context(), func() {
		// The session's WT_CLOSE_SESSION capsule and FIN may still be in
		// flight. QUIC doesn't deliver stream data sent before a
		// CONNECTION_CLOSE, so closing at once would make the peer see a
		// connection error in place of the session's close code. Wait a few
		// round trips for them to arrive, unless the peer closes first.
		t := time.NewTimer(closeConnGrace(qconn.ConnectionStats().SmoothedRTT))
		defer t.Stop()
		select {
		case <-t.C:
		case <-qconn.Context().Done():
		}
		qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	})
	return rsp, sess, nil
}

// Bounds of the wait between a dialed session ending and its QUIC connection
// closing (see closeConnGrace).
const (
	minCloseConnGrace = 50 * time.Millisecond
	maxCloseConnGrace = time.Second
)

// closeConnGrace returns how long Dial keeps a session's QUIC connection open
// after the session ends: three smoothed round trips, enough for the last
// stream data and a loss recovery, bounded so that a missing RTT sample or a
// slow path neither closes too early nor holds the connection open long.
func closeConnGrace(smoothedRTT time.Duration) time.Duration {
	return min(max(3*smoothedRTT, minCloseConnGrace), maxCloseConnGrace)
}

// Close cancels session establishment waiting for peer HTTP/3 settings.
// It doesn't close established sessions or QUIC connections passed to NewClientConn.
func (d *Transport) Close() error {
	d.ctxCancel()
	return nil
}
