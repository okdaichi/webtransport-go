package webtransport

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type quicSendStream interface {
	io.WriteCloser
	WriteWithLimit([]byte, func(int) int) (int, error)
	StreamID() quic.StreamID
	CancelWrite(quic.StreamErrorCode)
	Context() context.Context
	SetWriteDeadline(time.Time) error
	SetReliableBoundary()
	SetPriority(urgency int8, incremental bool)
}

var (
	_ quicSendStream = &quic.SendStream{}
	_ quicSendStream = &quic.Stream{}
)

// A SendStream is a unidirectional WebTransport send stream.
type SendStream struct {
	str          quicSendStream
	fc           *outgoingDataFlowController
	queueCapsule func(capsule)

	streamHdrMu sync.Mutex
	// WebTransport stream header.
	// Set by the constructor, set to nil once sent out.
	// Might be initialized to nil if this sendStream is part of an incoming bidirectional stream.
	streamHdr []byte
	// Set by Close or CancelWrite before sending a pending stream header asynchronously.
	// Prevents Write from sending payload before the header.
	writeErr error

	onClose func() // to remove the stream from the streamsMap

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error

	deadlineMu       sync.Mutex
	writeDeadline    time.Time
	deadlineNotifyCh chan struct{} // receives a value when deadline changes

	ctxMu     sync.Mutex
	ctx       context.Context         // set by Context
	ctxCancel context.CancelCauseFunc // cancels ctx; nil until Context is called
}

func newSendStream(
	str quicSendStream,
	hdr []byte,
	fc *outgoingDataFlowController,
	queueCapsule func(capsule),
	onClose func(),
) *SendStream {
	return &SendStream{
		str:          str,
		fc:           fc,
		queueCapsule: queueCapsule,
		closed:       make(chan struct{}),
		streamHdr:    hdr,
		onClose:      onClose,
	}
}

// StreamID returns the ID of the underlying QUIC stream.
func (s *SendStream) StreamID() quic.StreamID {
	return s.str.StreamID()
}

// Write writes data to the stream.
// Write can be made to time out using [SendStream.SetWriteDeadline].
// If the stream was canceled, the error is a [StreamError].
func (s *SendStream) Write(b []byte) (int, error) {
	n, err := s.write(b)
	var strErr *quic.StreamError
	if errors.As(err, &strErr) && strErr.ErrorCode == WTSessionGoneErrorCode {
		err = s.handleSessionGoneError()
	}
	if err != nil && !isTimeoutError(err) {
		s.onClose()
		s.syncContext()
	}
	return n, maybeConvertStreamError(err)
}

// handleSessionGoneError waits for the session to be closed after receiving a WTSessionGoneErrorCode.
// If the peer is initiating the session close, we might need to wait for the CONNECT stream to be closed.
// While a malicious peer might withhold the session close, this is not an interesting attack vector:
// 1. a WebTransport stream consumes very little memory, and
// 2. the number of concurrent WebTransport sessions is limited.
func (s *SendStream) handleSessionGoneError() error {
	s.deadlineMu.Lock()
	if s.deadlineNotifyCh == nil {
		s.deadlineNotifyCh = make(chan struct{}, 1)
	}
	s.deadlineMu.Unlock()

	for {
		s.deadlineMu.Lock()
		deadline := s.writeDeadline
		s.deadlineMu.Unlock()

		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			if d := time.Until(deadline); d > 0 {
				timerCh = time.After(d)
			} else {
				return os.ErrDeadlineExceeded
			}
		}
		select {
		case <-s.closed:
			return s.closeErr
		case <-timerCh:
			return os.ErrDeadlineExceeded
		case <-s.deadlineNotifyCh:
		}
	}
}

func (s *SendStream) write(b []byte) (int, error) {
	s.streamHdrMu.Lock()
	if s.writeErr != nil {
		err := s.writeErr
		s.streamHdrMu.Unlock()
		return 0, err
	}
	err := s.maybeSendStreamHeader()
	s.streamHdrMu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.writeData(b)
}

func (s *SendStream) writeData(b []byte) (int, error) {
	if s.fc == nil || len(b) == 0 {
		return s.str.Write(b)
	}

	var written int
	for len(b) > 0 {
		updated := s.fc.NextUpdate()
		n, err := s.str.WriteWithLimit(b, func(maxBytes int) int {
			return int(s.fc.AddBytesSent(int64(maxBytes)))
		})
		b = b[n:]
		written += n
		if err == nil {
			continue
		}
		if !errors.Is(err, quic.ErrWriteLimitReached) {
			return written, err
		}
		if blocked, maxData := s.fc.IsNewlyBlocked(); blocked {
			s.queueCapsule(dataBlockedCapsule{MaximumData: uint64(maxData)})
		}
		if err := s.waitForUpdate(updated); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (s *SendStream) waitForUpdate(updated <-chan struct{}) error {
	s.deadlineMu.Lock()
	if s.deadlineNotifyCh == nil {
		s.deadlineNotifyCh = make(chan struct{}, 1)
	}
	notifyCh := s.deadlineNotifyCh
	s.deadlineMu.Unlock()

	for {
		s.deadlineMu.Lock()
		deadline := s.writeDeadline
		s.deadlineMu.Unlock()

		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			if d := time.Until(deadline); d > 0 {
				timerCh = time.After(d)
			} else {
				return os.ErrDeadlineExceeded
			}
		}
		select {
		case <-s.str.Context().Done():
			return context.Cause(s.str.Context())
		case <-updated:
			return nil
		case <-timerCh:
			return os.ErrDeadlineExceeded
		case <-notifyCh:
		}
	}
}

func (s *SendStream) maybeSendStreamHeader() error {
	if len(s.streamHdr) == 0 {
		return nil
	}
	n, err := s.str.Write(s.streamHdr)
	if n > 0 {
		s.streamHdr = s.streamHdr[n:]
	}
	s.str.SetReliableBoundary()
	if err != nil {
		return err
	}
	s.streamHdr = nil
	return nil
}

// CancelWrite aborts sending on this stream.
// Data already written, but not yet delivered to the peer is not guaranteed to be delivered reliably.
// Write will unblock immediately, and future calls to Write will fail.
// When called multiple times it is a no-op.
func (s *SendStream) CancelWrite(e StreamErrorCode) {
	// if a Goroutine is already sending the header, return immediately
	s.streamHdrMu.Lock()
	if s.writeErr != nil {
		s.streamHdrMu.Unlock()
		return
	}

	if len(s.streamHdr) > 0 {
		// Sending the stream header might block if we are blocked by flow control.
		// Send a stream header async so that CancelWrite can return immediately.
		s.writeErr = &StreamError{ErrorCode: e}
		streamHdr := s.streamHdr
		s.streamHdr = nil
		s.streamHdrMu.Unlock()

		go func() {
			s.SetWriteDeadline(time.Time{})
			_, _ = s.str.Write(streamHdr)
			s.str.SetReliableBoundary()
			s.str.CancelWrite(webtransportCodeToHTTPCode(e))
			s.onClose()
			s.syncContext()
		}()
		return
	}
	s.streamHdrMu.Unlock()

	s.str.CancelWrite(webtransportCodeToHTTPCode(e))
	s.onClose()
	s.syncContext()
}

func (s *SendStream) closeWithSession(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		s.str.CancelWrite(WTSessionGoneErrorCode)
		close(s.closed)
		s.syncContext()
	})
}

// Close closes the write-direction of the stream.
// Future calls to Write are not permitted after calling Close.
func (s *SendStream) Close() error {
	// if a Goroutine is already sending the header, return immediately
	s.streamHdrMu.Lock()
	if s.writeErr != nil {
		s.streamHdrMu.Unlock()
		return nil
	}

	if len(s.streamHdr) > 0 {
		// Sending the stream header might block if we are blocked by flow control.
		// Send a stream header async so that CancelWrite can return immediately.
		s.writeErr = errors.New("write on closed stream")
		streamHdr := s.streamHdr
		s.streamHdr = nil
		s.streamHdrMu.Unlock()

		go func() {
			s.SetWriteDeadline(time.Time{})
			_, _ = s.str.Write(streamHdr)
			s.str.SetReliableBoundary()
			_ = s.str.Close()
			s.onClose()
			s.syncContext()
		}()
		return nil
	}
	s.streamHdrMu.Unlock()

	s.onClose()
	err := s.str.Close()
	s.syncContext()
	return maybeConvertStreamError(err)
}

// The Context is canceled as soon as the write-side of the stream is closed.
// This happens when Close() or CancelWrite() is called, or when the peer
// cancels the read-side of their stream.
// The cancellation cause is set to the error that caused the stream to
// close, or `context.Canceled` in case the stream is closed without error.
// When the peer canceled the stream with a WebTransport error code, the cause
// is a [StreamError] carrying that code, as Write would return it. When the
// stream ended because its session closed, the cause is the session's close
// error, as Write returns it. A reset with another code, such as the peer's
// WT_SESSION_GONE before its session close arrives, keeps the QUIC stream
// error.
//
// The context is done by the time Write, Close or CancelWrite returns having
// ended the stream.
func (s *SendStream) Context() context.Context {
	s.ctxMu.Lock()
	defer s.ctxMu.Unlock()
	if s.ctx == nil {
		parent := s.str.Context()
		s.ctx, s.ctxCancel = context.WithCancelCause(context.WithoutCancel(parent))
		if parent.Err() == nil {
			context.AfterFunc(parent, s.syncContext)
		} else if cause := s.contextCause(context.Cause(parent)); cause != nil {
			s.ctxCancel(cause)
		}
	}
	return s.ctx
}

// syncContext cancels the context Context returned, if any, once the QUIC
// stream's context has ended, so that it does not lag behind the call that
// ended the stream. Canceling it again is a no-op.
func (s *SendStream) syncContext() {
	s.ctxMu.Lock()
	cancel := s.ctxCancel
	s.ctxMu.Unlock()
	if cancel == nil {
		return
	}
	parent := s.str.Context()
	if parent.Err() == nil {
		return
	}
	if cause := s.contextCause(context.Cause(parent)); cause != nil {
		cancel(cause)
	}
}

// contextCause converts the QUIC stream context's cause to what Write reports
// for the same end of the stream. A cause it cannot convert is kept. It
// returns nil while the stream is being reset because its session closed but
// closeWithSession has not yet published the session's error: then
// closeWithSession cancels the context itself, once the error is set.
func (s *SendStream) contextCause(cause error) error {
	streamErr, ok := errors.AsType[*quic.StreamError](cause)
	if !ok {
		return cause
	}
	if streamErr.ErrorCode == WTSessionGoneErrorCode && !streamErr.Remote {
		// Only closeWithSession resets the stream with this code locally.
		return s.sessionCloseErr()
	}
	if wtErr, err := toStreamError(streamErr); err == nil {
		return wtErr
	}
	return cause
}

// sessionCloseErr returns the session's close error once closeWithSession has
// run, and nil before.
func (s *SendStream) sessionCloseErr() error {
	select {
	case <-s.closed:
		return s.closeErr
	default:
		return nil
	}
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some data was successfully written.
// A zero value for t means Write will not time out.
func (s *SendStream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	if s.deadlineNotifyCh != nil {
		select {
		case s.deadlineNotifyCh <- struct{}{}:
		default:
		}
	}
	s.deadlineMu.Unlock()

	return maybeConvertStreamError(s.str.SetWriteDeadline(t))
}

// SetPriority sets the scheduling priority for data sent on the stream.
// See [quic.SendStream.SetPriority] for the urgency/incremental semantics
// defined by RFC 9218.
func (s *SendStream) SetPriority(urgency int8, incremental bool) {
	s.str.SetPriority(urgency, incremental)
}
