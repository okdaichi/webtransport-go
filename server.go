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

// defaultReorderingTimeout is how long the per-connection session manager buffers
// WebTransport streams that arrive before their session's Extended CONNECT request.
// It is an internal connection-level concern and is intentionally not configurable
// on Server; the user-facing ReorderingTimeout (the SETTINGS wait during Upgrade)
// lives on Upgrader. It is a var so tests can shorten it.
var defaultReorderingTimeout = 5 * time.Second

// serverConnContext is the documented handoff point between Server and Upgrader.
//
// A Server stamps one of these onto every request context via its ConnContext hook.
// Upgrader.Upgrade has no back-reference to the Server, so this value is the single
// channel through which it reaches both the underlying QUIC connection and the
// per-connection stream router (sessionManager). Constructing an Upgrader and calling
// Upgrade outside of a Server-routed request returns an error.
type serverConnContext struct {
	conn           *quic.Conn
	sessionManager *sessionManager
}

type serverConnContextKeyType struct{}

var serverConnContextKey = serverConnContextKeyType{}

type Server struct {
	H3 *http3.Server

	ctx       context.Context // is closed when Close is called
	ctxCancel context.CancelFunc
	refCount  sync.WaitGroup

	initOnce sync.Once
	initErr  error

	connsMx sync.Mutex
	conns   map[*quic.Conn]*sessionManager
}

func (s *Server) initialize() error {
	s.initOnce.Do(func() {
		s.initErr = s.init()
	})
	return s.initErr
}

func (s *Server) init() error {
	if s.H3 == nil {
		return errors.New("webtransport: H3 server is required")
	}

	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	s.conns = make(map[*quic.Conn]*sessionManager)
	s.configureHTTP3Server()

	return nil
}

// configureHTTP3Server wires the HTTP/3 settings WebTransport requires and installs
// the ConnContext hook that stamps a serverConnContext onto each request context.
// Called from init(), so callers do not need to invoke it separately.
func (s *Server) configureHTTP3Server() {
	h3 := s.H3
	if h3.AdditionalSettings == nil {
		h3.AdditionalSettings = make(map[uint64]uint64, 6)
	}
	// send the old setting for backwards compatibility with older clients
	h3.AdditionalSettings[settingsEnableWebtransportDraft06] = 1
	h3.AdditionalSettings[settingsWebTransportEnabled] = 1

	// Safari requires SETTINGS_WT_MAX_SESSIONS >= 1 (draft-ietf-webtrans-http3-14)
	h3.AdditionalSettings[settingsWebTransportMaxSessions] = 1<<62 - 1

	// Required when SETTINGS_WT_MAX_SESSIONS > 1
	h3.AdditionalSettings[settingsWebTransportInitialMaxStreamsUni] = 1 << 60
	h3.AdditionalSettings[settingsWebTransportInitialMaxStreamsBidi] = 1 << 60
	h3.AdditionalSettings[settingsWebTransportInitialMaxData] = 1 << 60

	h3.EnableDatagrams = true
	origConnContext := h3.ConnContext
	h3.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		if origConnContext != nil {
			ctx = origConnContext(ctx, conn)
		}
		// The session manager is created by ServeQUICConn before this connection is
		// handed to the HTTP/3 layer, so it is already registered here.
		s.connsMx.Lock()
		sessManager := s.conns[conn]
		s.connsMx.Unlock()
		return context.WithValue(ctx, serverConnContextKey, &serverConnContext{
			conn:           conn,
			sessionManager: sessManager,
		})
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
		s.refCount.Go(func() {
			if err := s.ServeQUICConn(qconn); err != nil {
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

	// close the connection when the server context is cancelled.
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
				// read the frame type (already peeked)
				if _, err := quicvarint.Read(quicvarint.NewReader(str)); err != nil {
					return
				}
				// read the session ID
				id, err := quicvarint.Read(quicvarint.NewReader(str))
				if err != nil {
					str.CancelRead(quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError))
					str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError))
					return
				}
				if !isValidSessionID(id) {
					conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeIDError), "")
					return
				}
				sessMgr.AddStream(str, sessionID(id))
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
				r := quicvarint.NewReader(str)
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
				sessMgr.AddUniStream(str, sessionID(id))
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

func (s *Server) Close() error {
	// Make sure that ctxCancel is defined.
	// This is expected to be uncommon.
	// It only happens if the server is closed without Serve / ListenAndServe having been called.
	s.initOnce.Do(func() {})

	if s.ctxCancel != nil {
		s.ctxCancel()
	}
	s.connsMx.Lock()
	if s.conns != nil {
		for _, mgr := range s.conns {
			mgr.Close()
		}
		s.conns = nil
	}
	s.connsMx.Unlock()

	err := s.H3.Close()
	s.refCount.Wait()
	return err
}

// serverConnContextFromRequest returns the Server-provided connection context for r,
// or nil if r was not routed through a webtransport.Server.
func serverConnContextFromRequest(r *http.Request) *serverConnContext {
	v, _ := r.Context().Value(serverConnContextKey).(*serverConnContext)
	return v
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
