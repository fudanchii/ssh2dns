package recdns

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/fudanchii/ssh2dns/errors"
	"github.com/miekg/dns"
)

type Connection struct {
	net.Conn
}

func (pc *Connection) ReadMsgWithContext(ctx context.Context) (*dns.Msg, error) {
	errChan := make(chan error, 1)
	msgChan := make(chan *dns.Msg, 1)

	go func() {
		msg, err := pc.ReadMsg()
		if err != nil {
			errChan <- err
			return
		}

		msgChan <- msg
	}()

	select {
	case <-ctx.Done():
		return nil, errors.ConnectionTimeout{}
	case err := <-errChan:
		return nil, err
	case msg := <-msgChan:
		return msg, nil
	}
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L191
func (pc *Connection) ReadMsg() (*dns.Msg, error) {
	p, err := pc.ReadMsgHdr(nil)

	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)

	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}

	return m, err
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L217
func (pc *Connection) ReadMsgHdr(h *dns.Header) ([]byte, error) {
	l, err := tcpMsgLen(pc)

	if err != nil {
		return nil, err
	}

	p := make([]byte, l)
	_, err = tcpRead(pc, p)

	return p, err
}

func (pc *Connection) WriteMsgWithContext(ctx context.Context, msg *dns.Msg) error {
	errChan := make(chan error, 1)
	go func() {
		errChan <- pc.WriteMsg(msg)
	}()

	select {
	case <-ctx.Done():
		return errors.ConnectionTimeout{}
	case err := <-errChan:
		return err
	}
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L334
func (pc *Connection) WriteMsg(msg *dns.Msg) error {
	var (
		out []byte
		err error
	)

	out, err = msg.Pack()

	if err != nil {
		return err
	}

	_, err = pc.Write(out)
	return err
}

func (pc *Connection) Write(buff []byte) (int, error) {
	l := len(buff)
	nbuff := make([]byte, 2, l+2)
	binary.BigEndian.PutUint16(nbuff, uint16(l))
	nbuff = append(nbuff, buff...)
	return pc.Conn.Write(nbuff)
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L262
// tcpMsgLen is a helper func to read first two bytes of stream as uint16 packet length.
func tcpMsgLen(t io.Reader) (int, error) {
	p := []byte{0, 0}
	n, err := t.Read(p)
	if err != nil {
		return 0, err
	}

	// As seen with my local router/switch, returns 1 byte on the above read,
	// resulting a a ShortRead. Just write it out (instead of loop) and read the
	// other byte.
	if n == 1 {
		_, err := t.Read(p[1:])
		if err != nil {
			return 0, err
		}
	}

	l := binary.BigEndian.Uint16(p)
	return int(l), nil
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L291
// tcpRead calls TCPConn.Read enough times to fill allocated buffer.
func tcpRead(t io.Reader, p []byte) (int, error) {
	n, err := t.Read(p)
	if err != nil {
		return n, err
	}
	for n < len(p) {
		j, err := t.Read(p[n:])
		if err != nil {
			return n, err
		}
		n += j
	}
	return n, err
}
