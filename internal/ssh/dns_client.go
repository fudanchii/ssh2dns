package ssh

import (
	"context"

	"github.com/fudanchii/ssh2dns/internal/errors"
	"github.com/miekg/dns"
)

func (sshCli *Client) ExchangeWithContext(ctx context.Context, req *dns.Msg, srv string) (*dns.Msg, error) {
	conn, err := sshCli.DialTCPWithContext(ctx, srv)
	if err != nil {
		retErr := errors.DNSDialErr{Cause: err}
		go func() { sshCli.errLoopBack <- retErr }()
		return nil, retErr
	}

	defer conn.Close()

	dnsConn := &Connection{Conn: conn}
	if err = dnsConn.WriteMsgWithContext(ctx, req); err != nil {
		return nil, errors.DNSWriteErr{Cause: err}
	}

	rspMsg, err := dnsConn.ReadMsgWithContext(ctx)
	if err != nil {
		return nil, errors.DNSReadErr{Cause: err}
	}

	go func() { sshCli.errLoopBack <- errResetErrCount }()

	return rspMsg, nil
}
