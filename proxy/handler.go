package proxy

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/fudanchii/ssh2dns/config"
	"github.com/fudanchii/ssh2dns/log"
	"github.com/fudanchii/ssh2dns/recdns"
	"github.com/fudanchii/ssh2dns/ssh"

	"github.com/miekg/dns"
	"github.com/sourcegraph/conc/pool"
	"golang.org/x/sync/singleflight"
)

type proxyRequest struct {
	message    *dns.Msg
	sshClient  *ssh.Client
	rspChannel chan *dns.Msg
	errChannel chan error
}

type Proxy struct {
	srv         *dns.Server
	workers     *pool.Pool
	flightGroup singleflight.Group
	config      *config.AppConfig
	clientPool  *ssh.ClientPool
	rdns        *recdns.LookupCoordinator
}

func New(cfg *config.AppConfig, clientPool *ssh.ClientPool) *Proxy {
	var proxy = Proxy{
		config:     cfg,
		clientPool: clientPool,
		workers:    pool.New().WithMaxGoroutines(cfg.WorkerNum() * 2),
		srv:        &dns.Server{Addr: cfg.BindAddr(), Net: "udp"},
		rdns:       recdns.New(cfg),
	}

	dns.HandleFunc(".", proxy.handler)

	return &proxy
}

func (proxy *Proxy) handleRequest(req *proxyRequest) {
	rspMessage, err := proxy.rdns.Handle(req.message, req.sshClient)

	if err != nil {
		req.errChannel <- fmt.Errorf("error handling lookup: %s", err.Error())
		return
	}

	req.rspChannel <- rspMessage
}

func (proxy *Proxy) handler(w dns.ResponseWriter, r *dns.Msg) {
	var (
		msg *dns.Msg
		err error
	)

	rsp := new(dns.Msg)
	rsp.SetReply(r)

	start := time.Now()

	msg, hit := proxy.rdns.CacheLookup(r)

	if !hit {
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

	logRequest(rsp, hit, end.Sub(start))

	if err = w.WriteMsg(rsp); err != nil {
		log.Err(err.Error())
		return
	}
}

func (proxy *Proxy) ListenAndServe() error {
	return proxy.srv.ListenAndServe()
}

func (proxy *Proxy) Shutdown() {
	log.Info("stop listening...")
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(5)*time.Second)
	defer cancel()
	if err := proxy.srv.ShutdownContext(ctx); err != nil {
		log.Err(err.Error())
	}
	log.Info("waiting workers to finish...")
	proxy.workers.Wait()
	log.Info("closing remote connections...")
	proxy.clientPool.Close()
}

func (proxy *Proxy) singleFlightRequestHandler(r *dns.Msg) (*dns.Msg, error) {
	rsp, err, _ := proxy.flightGroup.Do(strconv.Itoa(int(r.MsgHdr.Id)), func() (interface{}, error) {
		rspChannel := make(chan *dns.Msg, 1)
		errChannel := make(chan error, 1)

		sshClient, err := proxy.clientPool.Acquire(context.TODO())
		if err != nil {
			return nil, err
		}
		defer sshClient.Release()

		pReq := &proxyRequest{
			message:    r,
			sshClient:  sshClient.Value(),
			rspChannel: rspChannel,
			errChannel: errChannel,
		}

		proxy.workers.Go(func() { proxy.handleRequest(pReq) })

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
