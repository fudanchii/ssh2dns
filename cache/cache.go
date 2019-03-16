package cache

import (
	"time"

	. "github.com/fudanchii/socks5dns/config"

	"github.com/allegro/bigcache"
	"github.com/miekg/dns"
)

var (
	cache *bigcache.BigCache
)

func init() {
	cache, _ = bigcache.NewBigCache(bigcache.DefaultConfig(10 * time.Minute))
}

func Get(r *dns.Msg) (*dns.Msg, bool) {
	if !Config.UseCache {
		return nil, false
	}

	r.Answer = []dns.RR{}
	for _, q := range r.Question {
		cval, err := cache.Get(keying(q.Name, q.Qtype))
		if err != nil {
			return nil, false
		}

		rr, err := dns.NewRR(string(cval))
		if err != nil {
			return nil, false
		}

		r.Answer = append(r.Answer, rr)
	}

	return r, true
}

func Set(m *dns.Msg) {
	if !Config.UseCache {
		return
	}

	for _, a := range m.Answer {
		h := a.Header()
		cache.Set(keying(h.Name, h.Rrtype), []byte(a.String()))
	}
}

func keying(name string, ty uint16) string {
	return dns.TypeToString[ty] + ":" + name
}
