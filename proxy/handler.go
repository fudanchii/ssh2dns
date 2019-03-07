package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/fudanchii/socks5dns/log"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"

	. "github.com/fudanchii/socks5dns/config"
	sh "github.com/fudanchii/socks5dns/ssh"
)

type ProxyRequest struct {
	message    *dns.Msg
	rspChannel chan *dns.Msg
	errChannel chan error
}

var (
	workers     = make([]*ProxyWorker, Config.WorkerNum)
	waitChannel = make(chan bool)
)

func init() {
	go func() {
		for i, _ := range workers {
			workers[i] = &ProxyWorker{
				sshClient:  sh.Connect(),
				reqChannel: make(chan *ProxyRequest),
			}
		}

		log.Info(fmt.Sprintf("running %d worker connections", Config.WorkerNum))

		for _, worker := range workers {
			go func(worker *ProxyWorker) {
				for request := range worker.reqChannel {
					worker.handleRequest(request)
				}
			}(worker)
		}

		waitChannel <- true
	}()
}

type ProxyConnection struct {
	net.Conn
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L191
func (pc *ProxyConnection) ReadMsg() (*dns.Msg, error) {
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
func (pc *ProxyConnection) ReadMsgHdr(h *dns.Header) ([]byte, error) {
	l, err := tcpMsgLen(pc)

	if err != nil {
		return nil, err
	}

	p := make([]byte, l)
	_, err = tcpRead(pc, p)

	return p, err
}

// https://github.com/miekg/dns/blob/164b22ef9acc6ebfaef7169ab51caaef67390823/client.go#L334
func (pc *ProxyConnection) WriteMsg(msg *dns.Msg) error {
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

func (pc *ProxyConnection) Write(buff []byte) (int, error) {
	l := len(buff)
	nbuff := make([]byte, 2, l+2)
	binary.BigEndian.PutUint16(nbuff, uint16(l))
	nbuff = append(nbuff, buff...)
	return pc.Conn.Write(nbuff)
}

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
		n1, err := t.Read(p[1:])
		if err != nil {
			return 0, err
		}
		n += n1
	}

	l := binary.BigEndian.Uint16(p)
	return int(l), nil
}

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

type ProxyWorker struct {
	sshClient  *ssh.Client
	reqChannel chan *ProxyRequest
}

func (w *ProxyWorker) handleRequest(req *ProxyRequest) {
	conn, err := w.sshClient.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		req.errChannel <- fmt.Errorf("error dialing DNS: %s", err.Error())
		return
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(Config.ConnTimeout) * time.Second))

	dnsConn := &ProxyConnection{Conn: conn}
	if err = dnsConn.WriteMsg(req.message); err != nil {
		req.errChannel <- fmt.Errorf("error writing DNS request: %s", err.Error())
		return
	}

	rspMessage, err := dnsConn.ReadMsg()
	if err != nil {
		req.errChannel <- fmt.Errorf("error reading DNS response: %s", err.Error())
		return
	}

	req.rspChannel <- rspMessage
}

func Handler(w dns.ResponseWriter, r *dns.Msg) {
	rsp := new(dns.Msg)
	rsp.SetReply(r)

	rspChannel := make(chan *dns.Msg, 1)
	errChannel := make(chan error, 1)
	pReq := ProxyRequest{
		message:    r,
		rspChannel: rspChannel,
		errChannel: errChannel,
	}
	timeout := time.After(time.Duration(Config.ConnTimeout) * time.Second)

	logQuestions(r)

	go selectWorker(&pReq, timeout)

	select {
	case msg := <-rspChannel:
		if len(msg.Answer) > 0 {
			rsp.Answer = msg.Answer
		}
		if len(msg.Ns) > 0 {
			rsp.Ns = msg.Ns
		}
		if len(msg.Extra) > 0 {
			rsp.Extra = msg.Extra
		}
	case err := <-errChannel:
		log.Err(err.Error())
	}

	w.WriteMsg(rsp)
}

func Wait() {
	<-waitChannel
}

func selectWorker(r *ProxyRequest, timeout <-chan time.Time) {
	for _, worker := range workers {
		select {
		case <-timeout:
			return
		case worker.reqChannel <- r:
			return
		case <-time.After(10 * time.Microsecond):
			continue
		}
	}
}

func logQuestions(m *dns.Msg) {
	for _, q := range m.Question {
		log.Info(fmt.Sprintf("(%6d) %4s %s", m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name))
	}
}
