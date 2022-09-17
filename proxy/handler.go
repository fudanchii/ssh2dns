package proxy

import (
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fudanchii/ssh2dns/cache"
	"github.com/fudanchii/ssh2dns/log"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/fudanchii/ssh2dns/config"
	"github.com/fudanchii/ssh2dns/ssh"
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

func (w *proxyWorker) reconnect() {
	w.sshClient.Drop()
	rchan := w.reqChannel
	w.reqChannel = nil // set to nil so it never get selected

	// blocking here until we get new connection
	w.sshClient = w.sshClient.Reconnect()
	w.reqChannel = rchan
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

	proxy.setCache(req.message, rspMessage)

	req.rspChannel <- rspMessage
}

const errThreshold = 10

type Proxy struct {
	workers      []*proxyWorker
	waitChannel  chan bool
	flightGroup  singleflight.Group
	config       *config.AppConfig
	cache        *cache.Cache
	clientPool   *ssh.ClientPool
	errCounter   atomic.Uint32
	reconnecting atomic.Bool
	reconnectCh  chan struct{}
}

func New(cfg *config.AppConfig, clientPool *ssh.ClientPool, cachee *cache.Cache) *Proxy {
	var proxy = Proxy{
		workers:     make([]*proxyWorker, cfg.WorkerNum()),
		waitChannel: make(chan bool, 1),
		config:      cfg,
		cache:       cachee,
		clientPool:  clientPool,
		reconnectCh: make(chan struct{}),
	}

	go func(proxy *Proxy) {
		log.Info(fmt.Sprintf("running %d worker connections", cfg.WorkerNum()))

		for i := range proxy.workers {
			proxy.workers[i] = &proxyWorker{
				sshClient:  proxy.clientPool.Connect(),
				reqChannel: make(chan *proxyRequest),
				config:     proxy.config,
			}
		}

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
	msg, cacheHit = proxy.getCache(r)
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

	logRequest(rsp, cacheHit, end.Sub(start))

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

func (proxy *Proxy) handleError() {
	if proxy.errCounter.CompareAndSwap(errThreshold, errThreshold) {
		log.Info("[handleError] more than threshold, already processed")
		return
	}

	if nv := proxy.errCounter.Add(1); nv < errThreshold {
		log.Info("[handleError] no further process needed")
		return
	}

	if proxy.reconnecting.CompareAndSwap(false, true) {
		log.Info("reconnecting all workers")

		close(proxy.reconnectCh)

		var wg sync.WaitGroup
		for _, w := range proxy.workers {
			wg.Add(1)
			go func(w *proxyWorker) {
				defer wg.Done()
				w.reconnect()
			}(w)
		}
		wg.Wait()

		log.Info("all workers reconnected")
		proxy.reconnecting.Store(false)
		proxy.reconnectCh = make(chan struct{})
		proxy.errCounter.Store(0)
	}
}

func (proxy *Proxy) singleFlightRequestHandler(r *dns.Msg) (*dns.Msg, error) {
	if proxy.reconnecting.Load() == true {
		return nil, fmt.Errorf("cannot handle request now")
	}

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
			go proxy.handleError()
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
	cases := make([]reflect.SelectCase, len(proxy.workers)+2)
	cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(timeout),
		Send: reflect.ValueOf(nil),
	}

	cases[1] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(proxy.reconnectCh),
		Send: reflect.ValueOf(nil),
	}

	for x, worker := range proxy.workers {
		cases[x+2] = reflect.SelectCase{
			Dir:  reflect.SelectSend,
			Chan: reflect.ValueOf(worker.reqChannel),
			Send: reflect.ValueOf(r),
		}
	}

	chosen, _, _ := reflect.Select(cases)
	if chosen == 0 {
		r.errChannel <- fmt.Errorf("timeout")
	}
	if chosen == 1 {
		r.errChannel <- fmt.Errorf("reconnecting, cannot process this request")
	}
}

func (proxy *Proxy) getCache(req *dns.Msg) (*dns.Msg, bool) {
	if proxy.config.UseCache() {
		return proxy.cache.Get(req)
	}
	return nil, false
}

func (proxy *Proxy) setCache(req *dns.Msg, rsp *dns.Msg) {
	if !proxy.config.UseCache() || proxy.cache == nil {
		return
	}
	proxy.cache.Set(req, rsp)
}

func logRequest(m *dns.Msg, cacheHit bool, d time.Duration) {
	for _, a := range m.Question {
		log.Info(fmt.Sprintf(
			"[%s] (%5d) %5s %s %s",
			hitOrMiss(cacheHit),
			m.MsgHdr.Id,
			dns.TypeToString[a.Qtype],
			a.Name,
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
