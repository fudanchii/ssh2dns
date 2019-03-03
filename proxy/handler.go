package proxy

import (
	_ "github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/ssh"
	"github.com/miekg/dns"
)

type ProxyWorker struct {
	sshClient  *ssh.Client
	reqChannel chan *ProxyRequest
}

type ProxyRequest struct {
	message    *dns.Msg
	rspChannel chan *dns.Msg
	errChannel chan error
}

var workers = make([]*ProxyWorker, config.WorkerNum)

func init() {
	for i, _ := range workers {
		workers[i] = &ProxyWorker{
			sshClient:  ssh.Reconnect(),
			reqChannel: make(chan *ProxyRequest),
		}
	}

	for _, worker := range workers {
		go func(worker *ProxyWorker) {
			for request := range worker.reqChannel {
				worker.handlRequest(request)
			}
		}(worker)
	}
}

func (w *worker) handleRequest(req ProxyRequest) {
	conn, err := w.sshClient.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		req.errChannel <- err
		return
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(Config.ConnTimeout) * time.Second))

	dnsConn := &dns.Conn{Conn: conn}
	if err = dnsConn.WriteMsg(&req.message); err != nil {
		req.errChannel <- err
		return
	}

	rspMessage, err := dnsConn.ReadMsg()
	if err != nil {
		req.errChannel <- err
		return
	}

	req.rspChannel <- rspMessage
}

func Handler(w *dns.ResponseWriter, r *dns.Msg) {
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

func selectWorker(r *ProxyRequest, timeout <-chan time.Time) {
	for _, worker := range workers {
		select {
		case <-timeout:
			return
		case worker.reqChannel <- r:
			return
		case <-time.After(10 * time.MicroSecond):
			continue
		}
	}
}
