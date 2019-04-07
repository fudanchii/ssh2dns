package proxy

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/fudanchii/socks5dns/cache"
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
	conn, err := w.sshClient.Dial("tcp", Config.TargetServer)
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

	cache.Set(rspMessage)

	req.rspChannel <- rspMessage
}

func Handler(w dns.ResponseWriter, r *dns.Msg) {
	var (
		msg      *dns.Msg
		err      error
		cacheHit bool
	)

	rsp := new(dns.Msg)
	rsp.SetReply(r)

	start := time.Now()

	// cacheHit will always false if UseCache is false
	msg, cacheHit = cache.Get(r)
	if !cacheHit {
		msg, err = singleFlightRequestHandler(r)
	}

	end := time.Now()

	if err != nil {
		log.Err(err.Error())
		return
	}

	if len(msg.Answer) > 0 {
		rsp.Answer = msg.Answer
	}
	if len(msg.Ns) > 0 {
		rsp.Ns = msg.Ns
	}
	if len(msg.Extra) > 0 {
		rsp.Extra = msg.Extra
	}

	logResponse(rsp, cacheHit, end.Sub(start))

	w.WriteMsg(rsp)
}

func Wait() {
	<-waitChannel
}

func singleFlightRequestHandler(r *dns.Msg) (*dns.Msg, error) {
	rsp, err, _ := flightGroup.Do(strconv.Itoa(int(r.MsgHdr.Id)), func() (interface{}, error) {
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

	// this ensure type assertion below is always success
	if err != nil {
		return nil, err
	}

	return rsp.(*dns.Msg), nil
}

func selectWorker(r *ProxyRequest, timeout <-chan time.Time) {
	cases := make([]reflect.SelectCase, len(workers)+1)
	cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(timeout),
		Send: reflect.ValueOf(nil),
	}

	for x, worker := range workers {
		cases[x+1] = reflect.SelectCase{
			Dir:  reflect.SelectSend,
			Chan: reflect.ValueOf(worker.reqChannel),
			Send: reflect.ValueOf(r),
		}
	}

	if chosen, _, _ := reflect.Select(cases); chosen == 0 {
		r.errChannel <- fmt.Errorf("timeout")
	}
}

func sflightKey(m *dns.Msg) string {
	s := ""
	for _, q := range m.Question {
		s = fmt.Sprintf("%s%s%s", s, dns.TypeToString[q.Qtype], q.Name)
	}
	return s
}

func logResponse(m *dns.Msg, cacheHit bool, d time.Duration) {
	for _, a := range m.Answer {
		h := a.Header()
		log.Info(fmt.Sprintf("[%s] (%5d) %4s %s %s", hitOrMiss(cacheHit), m.MsgHdr.Id, dns.TypeToString[h.Rrtype], h.Name, d.String()))
	}
}

func hitOrMiss(c bool) string {
	if c {
		return "H"
	}
	return "M"
}
