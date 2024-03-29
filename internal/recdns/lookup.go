package recdns

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/fudanchii/ssh2dns/internal/cache"
	"github.com/fudanchii/ssh2dns/internal/config"
	"github.com/fudanchii/ssh2dns/internal/errors"
	"github.com/miekg/dns"
	"github.com/samber/lo"
)

type LookupCoordinator struct {
	cache            *cache.Cache
	rootMap          []*dns.A
	fallbackTargetNS net.IP
	clientPool       DNSClientPool
	recursive        bool
}

var (
	DefaultTimeout time.Duration = time.Duration(5) * time.Second
)

func New(cfg *config.AppConfig, clientPool DNSClientPool) *LookupCoordinator {
	cc := cache.New(cfg)
	lc := &LookupCoordinator{
		cache:            cc,
		rootMap:          []*dns.A{},
		fallbackTargetNS: cfg.TargetServerIPv4(),
		clientPool:       clientPool,
		recursive:        cfg.RecursiveLookup(),
	}
	lc.setup()
	return lc
}

func (lc *LookupCoordinator) handleRecursive(ctx context.Context, msg *dns.Msg, srv net.IP) (*dns.Msg, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	cli, err := lc.clientPool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	defer cli.Release()

	rspMsg, err := cli.Value().ExchangeWithContext(ctx, msg, strings.Join([]string{srv.String(), "53"}, ":"))
	if err != nil {
		return nil, err
	}

	if len(rspMsg.Answer) > 0 {
		rspMsg, err := lc.assertAnswerForQuestion(ctx, msg, rspMsg)
		if err == nil {
			lc.cache.Set(msg, rspMsg)
			return rspMsg, nil
		}
	}

	return lc.useNextNS(ctx, msg, rspMsg)
}

func (lc *LookupCoordinator) useNextNS(ctx context.Context, msg *dns.Msg, response *dns.Msg) (*dns.Msg, error) {
	var (
		err     error
		result  *dns.Msg
		nextSrv []dns.RR
		extra   []dns.RR
	)

	for _, ns := range response.Ns {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		nextNsString := ""
		nextNs, ok := ns.(*dns.NS)
		if !ok {
			if soa, ok := ns.(*dns.SOA); ok {
				nextNsString = soa.Ns
			} else {
				err = errors.AuthorityIsNotNS{Ns: ns}
				continue
			}
		} else {
			nextNsString = nextNs.Ns
		}

		if len(response.Extra) > 0 {
			nextSrv = lo.Filter(response.Extra, func(item dns.RR, _ int) bool {
				if item.Header().Rrtype == dns.TypeA {
					return item.Header().Name == nextNsString
				}
				return false
			})

			extra = response.Extra
		} else {
			nsQMsg := newQuestionMsg(nextNsString)
			nextNsAnswer, exist := lc.CacheLookup(nsQMsg)
			if !exist {
				nextNsAnswer, err = lc.tryHandleFromRoots(ctx, nsQMsg)
				if err != nil {
					return nil, err
				}
			}

			nextSrv = lo.Filter(nextNsAnswer.Answer, func(item dns.RR, _ int) bool {
				return item.Header().Rrtype == dns.TypeA
			})

			extra = nextNsAnswer.Extra
		}

		if len(nextSrv) == 0 {
			err = errors.NoARecordsForNS{Ns: ns, Extra: extra}
			continue
		}

		for _, nextDNS := range nextSrv {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			newSrv := nextDNS.(*dns.A).A
			result, err = lc.handleRecursive(ctx, msg, newSrv)
			if err != nil || result == nil || len(result.Answer) < 1 {
				continue
			}
			return result, nil
		}
	}
	return nil, err
}

func (lc *LookupCoordinator) Handle(msg *dns.Msg) (*dns.Msg, error) {
	errChan := make(chan error, 1)
	msgChan := make(chan *dns.Msg, 1)
	ctx, cancel := context.WithTimeout(context.TODO(), DefaultTimeout)
	defer cancel()

	fallbackLookup := func(err error) (*dns.Msg, error) {
		if err != nil && !lc.recursive {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.TODO(), DefaultTimeout)
		defer cancel()
		answer, err := lc.handleRecursive(ctx, msg, lc.fallbackTargetNS)
		if err != nil {
			return nil, errors.DomainNotFound{N: msg.Question[0].Name}.Wrap(err)
		}
		return answer, nil
	}

	go func() {
		var (
			msg *dns.Msg
			err error
		)
		if lc.recursive {
			msg, err = lc.tryHandleFromRoots(ctx, msg)
		} else {
			msg, err = fallbackLookup(nil)
		}
		if err != nil {
			errChan <- err
		} else {
			msgChan <- msg
		}
	}()

	select {
	case msg := <-msgChan:
		return msg, nil
	case err := <-errChan:
		return fallbackLookup(err)
	case <-ctx.Done():
		return fallbackLookup(errors.DomainNotFound{N: msg.Question[0].Name}.Wrap(ctx.Err()))
	}
}

func (lc *LookupCoordinator) tryHandleFromRoots(ctx context.Context, msg *dns.Msg) (answerMsg *dns.Msg, err error) {
	for _, ns := range lc.rootMap {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		answerMsg, err = lc.handleRecursive(ctx, msg, ns.A)
		if err == nil && answerMsg != nil && len(answerMsg.Answer) > 0 {
			return answerMsg, nil
		}
	}
	return nil, err
}

func (lc *LookupCoordinator) assertAnswerForQuestion(ctx context.Context, question *dns.Msg, answer *dns.Msg) (*dns.Msg, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if slices.ContainsFunc(answer.Answer, func(rr dns.RR) bool {
		return rr.Header().Rrtype == question.Question[0].Qtype
	}) {
		return answer, nil
	}

	if answer.Answer[0].Header().Rrtype == dns.TypeCNAME && !slices.ContainsFunc(answer.Answer, func(rr dns.RR) bool {
		return rr.Header().Rrtype == dns.TypeA
	}) {
		cname, _ := answer.Answer[0].(*dns.CNAME)
		cnameQMsg := newQuestionMsg(cname.Target)
		newAnswer, err := lc.tryHandleFromRoots(ctx, cnameQMsg)
		if err != nil {
			return nil, err
		}
		answer.Answer = append(answer.Answer, newAnswer.Answer...)
		return answer, nil
	}

	return answer, nil
}

func (lc *LookupCoordinator) setup() {
	r := strings.NewReader(rootHints)
	zp := dns.NewZoneParser(r, ".", "root.hints")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if a, ok := rr.(*dns.A); ok {
			lc.rootMap = append(lc.rootMap, a)
			lc.cache.SetFromRR(rr)
		}

	}
}

func (lc *LookupCoordinator) Close() {
	lc.clientPool.Close()
}

func (lc *LookupCoordinator) CacheLookup(req *dns.Msg) (*dns.Msg, bool) {
	return lc.cache.Get(req)
}

func newQuestionMsg(domain string) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(domain, dns.TypeA)
	return msg
}
