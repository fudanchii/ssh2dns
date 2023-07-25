package recdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fudanchii/ssh2dns/cache"
	"github.com/fudanchii/ssh2dns/config"
	"github.com/fudanchii/ssh2dns/errors"
	"github.com/fudanchii/ssh2dns/ssh"
	"github.com/miekg/dns"
	"github.com/samber/lo"
)

type LookupCoordinator struct {
	cache   *cache.Cache
	rootMap []*dns.A
}

func New(cfg *config.AppConfig) *LookupCoordinator {
	cc := cache.New(cfg)
	lc := &LookupCoordinator{
		cache:   cc,
		rootMap: []*dns.A{},
	}
	lc.setup()
	return lc
}

func (lc *LookupCoordinator) handleRecursive(msg *dns.Msg, sshCli *ssh.Client, srv net.IP) (*dns.Msg, error) {
	var closeOnce sync.Once

	ctx, cancelCtx := context.WithTimeout(context.TODO(), time.Duration(5)*time.Second)
	defer cancelCtx()

	conn, err := sshCli.DialTCPWithContext(ctx, fmt.Sprintf("%s:53", srv.String()))
	if err != nil {
		return nil, fmt.Errorf("error dialing DNS: %s", err.Error())
	}

	closeConn := func() { conn.Close() }

	defer closeOnce.Do(closeConn)

	writeCtx, cancelWriteCtx := context.WithTimeout(context.TODO(), time.Duration(5)*time.Second)
	defer cancelWriteCtx()
	dnsConn := &Connection{Conn: conn}
	if err = dnsConn.WriteMsgWithContext(writeCtx, msg); err != nil {
		return nil, fmt.Errorf("error writing DNS request: %s", err.Error())
	}

	readCtx, cancelReadCtx := context.WithTimeout(context.TODO(), time.Duration(5)*time.Second)
	defer cancelReadCtx()
	rspMsg, err := dnsConn.ReadMsgWithContext(readCtx)
	if err != nil {
		return nil, fmt.Errorf("error reading DNS response: %s", err.Error())
	}

	if len(rspMsg.Answer) > 0 {
		rspMsg, err := lc.assertAnswerForQuestion(msg, rspMsg, sshCli)
		if err == nil {
			lc.cache.Set(msg, rspMsg)
			return rspMsg, nil
		}
	}

	closeOnce.Do(closeConn)
	return lc.useNextNS(msg, rspMsg, sshCli)
}

func (lc *LookupCoordinator) useNextNS(msg *dns.Msg, crsp *dns.Msg, sshCli *ssh.Client) (*dns.Msg, error) {
	if len(crsp.Ns) > 0 && len(crsp.Extra) > 0 {
		var (
			err error
			rsp *dns.Msg
		)
		for _, ns := range crsp.Ns {
			nextNs, _ := ns.(*dns.NS)
			nextSrv := lo.Filter(crsp.Extra, func(item dns.RR, _ int) bool {
				if a, ok := item.(*dns.A); ok {
					return a.Header().Name == nextNs.Ns
				}
				return false
			})
			if len(nextSrv) == 0 {
				err = errors.DomainNotFound{}
				continue
			}
			newSrv := nextSrv[0].(*dns.A).A
			rsp, err = lc.handleRecursive(msg, sshCli, newSrv)
			if err != nil || rsp == nil || len(rsp.Answer) < 1 {
				continue
			}
			return rsp, nil
		}
		return nil, err
	} else if len(crsp.Ns) > 0 {
		var (
			err error
			rsp *dns.Msg
		)
		for _, ns_ := range crsp.Ns {
			ns, ok := ns_.(*dns.NS)
			if !ok {
				continue
			}
			nsQMsg := newQuestionMsg(ns.Ns)
			nextNs, exist := lc.CacheLookup(nsQMsg)
			if !exist {
				nextNs, err = lc.tryHandleFromRoots(nsQMsg, sshCli)
				if err != nil {
					return nil, err
				}
			}
			rsp, err = lc.handleRecursive(msg, sshCli, nextNs.Answer[0].(*dns.A).A)
			if err != nil || rsp == nil || len(rsp.Answer) < 1 {
				continue
			}
			return rsp, nil
		}
		return nil, err
	}
	return nil, errors.DomainNotFound{N: msg.Question[0].Name}
}

func (lc *LookupCoordinator) Handle(msg *dns.Msg, sshClient *ssh.Client) (*dns.Msg, error) {
	return lc.tryHandleFromRoots(msg, sshClient)
}

func (lc *LookupCoordinator) tryHandleFromRoots(msg *dns.Msg, sshClient *ssh.Client) (*dns.Msg, error) {
	for _, ns := range lc.rootMap {
		answerMsg, err := lc.handleRecursive(msg, sshClient, ns.A)
		if err == nil && answerMsg != nil && len(answerMsg.Answer) > 0 {
			return answerMsg, nil
		}
	}
	return nil, errors.DomainNotFound{N: msg.Question[0].Name}
}

func (lc *LookupCoordinator) assertAnswerForQuestion(question *dns.Msg, answer *dns.Msg, sshCli *ssh.Client) (*dns.Msg, error) {
	if lo.ContainsBy(answer.Answer, func(rr dns.RR) bool {
		return rr.Header().Rrtype == question.Question[0].Qtype
	}) {
		return answer, nil
	}
	if answer.Answer[0].Header().Rrtype == dns.TypeCNAME {
		cname, _ := answer.Answer[0].(*dns.CNAME)
		cnameQMsg := newQuestionMsg(cname.Target)
		newAnswer, err := lc.tryHandleFromRoots(cnameQMsg, sshCli)
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

func (lc *LookupCoordinator) CacheLookup(req *dns.Msg) (*dns.Msg, bool) {
	return lc.cache.Get(req)
}

func newQuestionMsg(domain string) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(domain, dns.TypeA)
	return msg
}
