package webtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	wtAvailableProtocolsHeader = "WT-Available-Protocols"
	wtProtocolHeader           = "WT-Protocol"
)

const (
	webTransportFrameType     = 0x41
	webTransportUniStreamType = 0x54
)

// defaultReorderingTimeout governs the connection-level buffering of incoming
// WebTransport streams that arrive before their session's CONNECT request. It is
// intentionally a package var (so tests can shorten it) and distinct from
// Upgrader.ReorderingTimeout, which governs only the SETTINGS wait during Upgrade.
var defaultReorderingTimeout = 5 * time.Second

type Server struct {
	H3 *http3.Server

	// Config is the WebTransport configuration used for new sessions.
	// If nil, the zero value is used.
	Config *Config

	ctx       context.Context // is closed when Close is called
	ctxCancel context.CancelFunc
	refCount  sync.WaitGroup

	initOnce sync.Once
	initErr  error
	config   Config

	connsMx sync.Mutex
	conns   map[*quic.Conn]*sessionManager
	closed  bool
}

func (s *Server) initialize() error {
	s.initOnce.Do(func() {
		s.initErr = s.init()
	})
	return s.initErr
}

func (s *Server) init() error {
	if s.Config != nil {
		s.config = *s.Config
	}
	if s.H3 != nil {
		s.configureHTTP3Server(s.H3)
		s.config.addSettings(s.H3.AdditionalSettings)
	}

	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.conns = make(map[*quic.Conn]*sessionManager)
	return nil
}

// configureHTTP3Server configures the HTTP/3 server for WebTransport: it enables
// datagrams, advertises the WebTransport SETTINGS, and wraps ConnContext so each
// request context carries a serverConnContext (QUIC conn + session manager + Config)
// for Upgrader.Upgrade. It composes with any ConnContext the caller already set.
func (s *Server) configureHTTP3Server(h3 *http3.Server) {
	if h3.AdditionalSettings == nil {
		h3.AdditionalSettings = make(map[uint64]uint64, 3)
	}
	// send the old setting for backwards compatibility with older clients
	h3.AdditionalSettings[settingsEnableWebtransportDraft06] = 1
	h3.AdditionalSettings[settingsWebTransportEnabled] = 1

	// Safari requires SETTINGS_WT_MAX_SESSIONS >= 1 (draft-ietf-webtrans-http3-14)
	h3.AdditionalSettings[settingsWebTransportMaxSessions] = 1<<62 - 1

	h3.EnableDatagrams = true
	origConnContext := h3.ConnContext
	h3.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		if origConnContext != nil {
			ctx = origConnContext(ctx, conn)
		}
		s.connsMx.Lock()
		sessMgr := s.conns[conn]
		s.connsMx.Unlock()
		ctx = context.WithValue(ctx, serverConnContextKey, &serverConnContext{
			conn:           conn,
			sessionManager: sessMgr,
			config:         s.config,
		})
		return ctx
	}
}

func (s *Server) Serve(conn net.PacketConn) error {
	if err := s.initialize(); err != nil {
		return err
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	return s.serve(conn)
}

func (s *Server) serve(conn net.PacketConn) error {
	var quicConf *quic.Config
	if s.H3.QUICConfig != nil {
		quicConf = s.H3.QUICConfig.Clone()
	} else {
		quicConf = &quic.Config{}
	}
	quicConf.EnableDatagrams = true
	quicConf.EnableStreamResetPartialDelivery = true
	ln, err := quic.ListenEarly(conn, s.H3.TLSConfig, quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		qconn, err := ln.Accept(s.ctx)
		if err != nil {
			return err
		}

		if s.isClosed() {
			// Do not accept a new connection during shutdown
			qconn.CloseWithError(0, "")
			continue
		}

		s.refCount.Go(func() {
			err := s.ServeQUICConn(qconn)
			if errors.Is(err, http.ErrServerClosed) {
				return
			} else if err != nil {
				log.Printf("http3: error serving QUIC connection: %v", err)
			}
		})
	}
}

// ServeQUICConn serves a single QUIC connection.
func (s *Server) ServeQUICConn(conn *quic.Conn) error {
	connState := conn.ConnectionState()
	if !connState.SupportsDatagrams.Local {
		return errors.New("webtransport: QUIC DATAGRAM support required, enable it via QUICConfig.EnableDatagrams")
	}
	if !connState.SupportsStreamResetPartialDelivery.Local {
		return errors.New("webtransport: QUIC Stream Resets with Partial Delivery required, enable it via QUICConfig.EnableStreamResetPartialDelivery")
	}
	if err := s.initialize(); err != nil {
		return err
	}

	s.connsMx.Lock()

	if s.closed {
		// Shutting down, do not accept new connections
		s.connsMx.Unlock()
		conn.CloseWithError(0, "")
		return http.ErrServerClosed
	}

	sessMgr, ok := s.conns[conn]
	if !ok {
		sessMgr = newSessionManager(defaultReorderingTimeout)
		s.conns[conn] = sessMgr
	}
	s.connsMx.Unlock()

	// Clean up when connection closes
	context.AfterFunc(conn.Context(), func() {
		s.connsMx.Lock()
		delete(s.conns, conn)
		s.connsMx.Unlock()
		sessMgr.Close()
	})

	http3Conn, err := s.H3.NewRawServerConn(conn)
	if err != nil {
		return err
	}

	// Close the connection when the server context is cancelled.
	go func() {
		select {
		case <-s.ctx.Done():
			conn.CloseWithError(0, "")
		case <-conn.Context().Done():
			// connection already closed
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		for {
			str, err := conn.AcceptStream(s.ctx)
			if err != nil {
				return
			}

			wg.Go(func() {
				typ, err := quicvarint.Peek(str)
				if err != nil {
					return
				}
				if typ != webTransportFrameType {
					http3Conn.HandleRequestStream(str)
					return
				}
				r := &byteCountingReader{ByteReader: quicvarint.NewReader(str)}
				// read the frame type (already peeked)
				if _, err := quicvarint.Read(r); err != nil {
					return
				}
				// read the session ID
				id, err := quicvarint.Read(r)
				if err != nil {
					str.CancelRead(quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError))
					str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError))
					return
				}
				if !isValidSessionID(id) {
					conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeIDError), "")
					return
				}
				sessMgr.AddStream(str, sessionID(id), r.BytesRead)
			})
		}
	}()

	go func() {
		defer wg.Done()

		for {
			str, err := conn.AcceptUniStream(s.ctx)
			if err != nil {
				return
			}

			wg.Go(func() {
				typ, err := quicvarint.Peek(str)
				if err != nil {
					return
				}
				if typ != webTransportUniStreamType {
					http3Conn.HandleUnidirectionalStream(str)
					return
				}
				// read the stream type (already peeked) before passing to AddUniStream
				r := &byteCountingReader{ByteReader: quicvarint.NewReader(str)}
				if _, err := quicvarint.Read(r); err != nil {
					return
				}
				// read the session ID
				id, err := quicvarint.Read(r)
				if err != nil {
					str.CancelRead(quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError))
					return
				}
				if !isValidSessionID(id) {
					conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeIDError), "")
					return
				}
				sessMgr.AddUniStream(str, sessionID(id), r.BytesRead)
			})
		}
	}()

	wg.Wait()
	return nil
}

func (s *Server) ListenAndServe() error {
	if err := s.initialize(); err != nil {
		return err
	}
	s.refCount.Add(1)
	defer s.refCount.Done()

	addr := s.H3.Addr
	if addr == "" {
		addr = ":https"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	return s.serve(conn)
}

func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	if s.H3.TLSConfig == nil {
		s.H3.TLSConfig = &tls.Config{}
	}
	s.H3.TLSConfig.Certificates = []tls.Certificate{cert}
	return s.ListenAndServe()
}

func (s *Server) isClosed() bool {
	s.connsMx.Lock()
	defer s.connsMx.Unlock()

	return s.closed
}

func (s *Server) Close() error {
	_ = s.initialize()

	// Close the established connections first, while the listener's socket is still
	// open, so each CONNECTION_CLOSE frame is actually transmitted to the peer.
	s.connsMx.Lock()
	s.closed = true
	if s.conns != nil {
		for conn, mgr := range s.conns {
			conn.CloseWithError(0, "")
			mgr.Close()
		}
		s.conns = nil
	}
	s.connsMx.Unlock()

	if s.ctxCancel != nil {
		s.ctxCancel()
	}

	err := s.H3.Close()
	s.refCount.Wait()
	return err
}

// copied from https://github.com/gorilla/websocket
func checkSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return equalASCIIFold(u.Host, r.Host)
}

// copied from https://github.com/gorilla/websocket
func equalASCIIFold(s, t string) bool {
	for s != "" && t != "" {
		sr, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		tr, size := utf8.DecodeRuneInString(t)
		t = t[size:]
		if sr == tr {
			continue
		}
		if 'A' <= sr && sr <= 'Z' {
			sr = sr + 'a' - 'A'
		}
		if 'A' <= tr && tr <= 'Z' {
			tr = tr + 'a' - 'A'
		}
		if sr != tr {
			return false
		}
	}
	return s == t
}
