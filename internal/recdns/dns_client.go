package recdns

import (
	"context"

	"github.com/miekg/dns"
)

type DNSClient interface {
	ExchangeWithContext(ctx context.Context, req *dns.Msg, srv string) (*dns.Msg, error)
}
