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

	"github.com/fudanchii/socks5dns/config"
	sh "github.com/fudanchii/socks5dns/ssh"
)

type proxyRequest struct {
	message    *dns.Msg
	rspChannel chan *dns.Msg
	errChannel chan error
}

type proxyWorker struct {
	sshClient  *ssh.Client
	reqChannel chan *proxyRequest
	config     *config.AppConfig
}

func (w *proxyWorker) handleRequest(req *proxyRequest, proxy *Proxy) {
	conn, err := w.sshClient.Dial("tcp", w.config.TargetServer())
	if err != nil {
		req.errChannel <- fmt.Errorf("error dialing DNS: %s", err.Error())
		return
	}

	defer conn.Close()

	dnsConn := &Connection{Conn: conn}
	if err = dnsConn.WriteMsg(req.message); err != nil {
		req.errChannel <- fmt.Errorf("error writing DNS request: %s", err.Error())
		return
	}

	rspMessage, err := dnsConn.ReadMsg()
	if err != nil {
		req.errChannel <- fmt.Errorf("error reading DNS response: %s", err.Error())
		return
	}

	proxy.cache.Set(rspMessage)

	req.rspChannel <- rspMessage
}

type Proxy struct {
	workers     []*proxyWorker
	waitChannel chan bool
	flightGroup singleflight.Group
	config      *config.AppConfig
	cache       *cache.Cache
	clientPool  *sh.ClientPool
}

func New(cfg *config.AppConfig, clientPool *sh.ClientPool) *Proxy {
	var proxy = Proxy{
		workers:     make([]*proxyWorker, cfg.WorkerNum()),
		waitChannel: make(chan bool, 1),
		config:      cfg,
		cache:       cache.New(cfg),
		clientPool:  clientPool,
	}

	go func(proxy *Proxy) {
		for i := range proxy.workers {
			proxy.workers[i] = &proxyWorker{
				sshClient:  proxy.clientPool.Connect(),
				reqChannel: make(chan *proxyRequest),
				config:     proxy.config,
			}
		}

		log.Info(fmt.Sprintf("running %d worker connections", cfg.WorkerNum()))

		for _, worker := range proxy.workers {
			go func(worker *proxyWorker) {
				for request := range worker.reqChannel {
					worker.handleRequest(request, proxy)
				}
			}(worker)
		}

		proxy.waitChannel <- true
	}(&proxy)

	return &proxy
}

func (proxy *Proxy) handler(w dns.ResponseWriter, r *dns.Msg) {
	var (
		msg      *dns.Msg
		err      error
		cacheHit bool
	)

	rsp := new(dns.Msg)
	rsp.SetReply(r)

	start := time.Now()

	// cacheHit will always false if UseCache is false
	msg, cacheHit = proxy.cache.Get(r)
	if !cacheHit {
		msg, err = proxy.singleFlightRequestHandler(r)
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

	if err = w.WriteMsg(rsp); err != nil {
		log.Err(err.Error())
		return
	}
}

func (proxy *Proxy) Wait() {
	<-proxy.waitChannel
}

func (proxy *Proxy) ListenAndServe() error {
	dns.HandleFunc(".", proxy.handler)
	srv := &dns.Server{Addr: proxy.config.BindAddr(), Net: "udp"}
	return srv.ListenAndServe()
}

func (proxy *Proxy) singleFlightRequestHandler(r *dns.Msg) (*dns.Msg, error) {
	rsp, err, _ := proxy.flightGroup.Do(strconv.Itoa(int(r.MsgHdr.Id)), func() (interface{}, error) {
		rspChannel := make(chan *dns.Msg, 1)
		errChannel := make(chan error, 1)
		pReq := proxyRequest{
			message:    r,
			rspChannel: rspChannel,
			errChannel: errChannel,
		}
		timeout := time.After(time.Duration(proxy.config.ConnTimeout()) * time.Second)

		go proxy.selectWorker(&pReq, timeout)

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

func (proxy *Proxy) selectWorker(r *proxyRequest, timeout <-chan time.Time) {
	cases := make([]reflect.SelectCase, len(proxy.workers)+1)
	cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(timeout),
		Send: reflect.ValueOf(nil),
	}

	for x, worker := range proxy.workers {
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

func logResponse(m *dns.Msg, cacheHit bool, d time.Duration) {
	for _, a := range m.Answer {
		h := a.Header()
		log.Info(fmt.Sprintf(
			"[%s] (%5d) %5s %s %s",
			hitOrMiss(cacheHit),
			m.MsgHdr.Id,
			dns.TypeToString[h.Rrtype],
			h.Name,
			d.String(),
		))
	}
}

func hitOrMiss(c bool) string {
	if c {
		return "H"
	}
	return "M"
}
