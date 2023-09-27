package recdns

import (
	"context"

	"github.com/miekg/dns"
)

type DNSClient interface {
	ExchangeWithContext(ctx context.Context, req *dns.Msg, srv string) (*dns.Msg, error)
	Close() error
}

type DNSClientPool interface {
	Pool[DNSClient]
}

type Pool[T any] interface {
	Acquire(context.Context) (PoolItemWrapper[T], error)
	Close()
}

type PoolItemWrapper[T any] interface {
	Value() T
	Release()
}
