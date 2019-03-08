package proxy

import (
	"fmt"
	"time"

	"github.com/fudanchii/socks5dns/log"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"

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
	flightGroup = singleflight.Group{}
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

	logQuestions(req.message)

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

	genericMsg, err, _ := flightGroup.Do(sflightKey(r), func() (interface{}, error) {
		rspChannel := make(chan *dns.Msg, 1)
		errChannel := make(chan error, 1)
		pReq := ProxyRequest{
			message:    r,
			rspChannel: rspChannel,
			errChannel: errChannel,
		}
		timeout := time.After(time.Duration(Config.ConnTimeout) * time.Second)

		go selectWorker(&pReq, timeout)

		select {
		case msg := <-rspChannel:
			return msg, nil
		case err := <-errChannel:
			return nil, err
		}

	})

	if err != nil {
		log.Err(err.Error())
		return
	}

	msg := genericMsg.(*dns.Msg)

	if len(msg.Answer) > 0 {
		rsp.Answer = msg.Answer
	}
	if len(msg.Ns) > 0 {
		rsp.Ns = msg.Ns
	}
	if len(msg.Extra) > 0 {
		rsp.Extra = msg.Extra
	}

	w.WriteMsg(rsp)
}

func Wait() {
	<-waitChannel
}

func selectWorker(r *ProxyRequest, timeout <-chan time.Time) {
	for {
		for _, worker := range workers {
			select {
			case <-timeout:
				r.errChannel <- fmt.Errorf("timeout waiting in queue")
				return
			case worker.reqChannel <- r:
				return
			case <-time.After(10 * time.Microsecond):
				continue
			}
		}
	}
}

func sflightKey(m *dns.Msg) string {
	s := ""
	for _, q := range m.Question {
		s = fmt.Sprintf("%s%s%s", s, dns.TypeToString[q.Qtype], q.Name)
	}
	return s
}

func logQuestions(m *dns.Msg) {
	for _, q := range m.Question {
		log.Info(fmt.Sprintf("(%6d) %4s %s", m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name))
	}
}
