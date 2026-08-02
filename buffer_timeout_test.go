package webtransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// TestServerReorderedUpgradeRequestTimeout exercises the connection-level stream
// buffering window (defaultReorderingTimeout), which is an internal Server concern
// not exposed via the Upgrader. It lives in the internal test package so it can
// shorten that window.
func TestServerReorderedUpgradeRequestTimeout(t *testing.T) {
	timeout := scaleDuration(100 * time.Millisecond)
	prev := defaultReorderingTimeout
	defaultReorderingTimeout = timeout
	t.Cleanup(func() { defaultReorderingTimeout = prev })

	s := &Server{H3: &http3.Server{TLSConfig: TLSConf, EnableDatagrams: true}}
	defer s.Close()
	connChan := make(chan *Session)
	addInternalHandler(t, s, func(c *Session) { connChan <- c })

	udpConn, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	go s.Serve(udpConn)

	cconn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", port),
		&tls.Config{RootCAs: CertPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)

	// Open a new stream for a WebTransport session we'll establish later. Stream ID: 0.
	str := openWTStreamAndWrite(t, cconn, 4, []byte("foobar"))

	time.Sleep(2 * timeout)

	tr := &http3.Transport{EnableDatagrams: true}
	conn := tr.NewClientConn(cconn)

	// Reordering was too long. The stream should now have been reset by the server.
	_, err = str.Read([]byte{0})
	var streamErr *quic.StreamError
	require.ErrorAs(t, err, &streamErr)
	require.Equal(t, WTBufferedStreamRejectedErrorCode, streamErr.ErrorCode)

	// Now establish the session. Make sure we don't accept the stream.
	requestStr, err := conn.OpenRequestStream(context.Background())
	require.NoError(t, err)
	require.NoError(t, requestStr.SendRequestHeader(
		NewWebTransportRequest(t, fmt.Sprintf("https://localhost:%d/webtransport", port)),
	))
	rsp, err := requestStr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	sconn := <-connChan
	defer sconn.CloseWithError(0, "")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = sconn.AcceptStream(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Establish another stream and make sure it's accepted now.
	openWTStreamAndWrite(t, cconn, 4, []byte("raboof"))
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	sstr, err := sconn.AcceptStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(sstr)
	require.NoError(t, err)
	require.Equal(t, []byte("raboof"), data)
}

func addInternalHandler(t *testing.T, s *Server, connHandler func(*Session)) {
	t.Helper()
	upgrader := &Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/webtransport", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Logf("upgrading failed: %s", err)
			w.WriteHeader(404)
			return
		}
		connHandler(conn)
	})
	s.H3.Handler = mux
}

func openWTStreamAndWrite(t *testing.T, conn *quic.Conn, sessionID uint64, data []byte) *quic.Stream {
	t.Helper()
	str, err := conn.OpenStream()
	require.NoError(t, err)
	buf := quicvarint.Append(quicvarint.Append(nil, webTransportFrameType), sessionID)
	buf = append(buf, data...)
	_, err = str.Write(buf)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	return str
}
