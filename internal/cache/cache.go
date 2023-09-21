package cache

import (
	"fmt"
	"time"

	"github.com/fudanchii/ssh2dns/internal/config"
	"github.com/fudanchii/ssh2dns/internal/log"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
)

type Cache struct {
	rc     *ristretto.Cache
	config *config.AppConfig
}

type dnsCacheContent struct {
	Ts     time.Time
	Ttl    time.Duration
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

func New(cfg *config.AppConfig) *Cache {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})

	if err != nil {
		if cfg.UseCache() {
			log.Fatal(err.Error())
		}
		log.Err(err.Error())
		return nil
	}

	return &Cache{cache, cfg}
}

func (cache *Cache) Get(msg *dns.Msg) (*dns.Msg, bool) {
	cacheval, found := cache.rc.Get(keying(msg))
	if !found {
		return nil, found
	}

	actualval := cacheval.(dnsCacheContent)

	// evict cache when expired, cache 3 times longer than TTL
	if time.Now().After(actualval.Ts.Add(actualval.Ttl * 3 * time.Second)) {
		cache.rc.Del(keying(msg))
	}

	msg.Answer = actualval.Answer
	msg.Ns = actualval.Ns
	msg.Extra = actualval.Extra

	return msg, true
}

func (cache *Cache) Set(req *dns.Msg, msg *dns.Msg) {
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		// no cache for empty answers, authority, and additional sections
		return
	}

	firstSection := getFirstAvailableSection(msg)

	cache.rc.Set(keying(req), dnsCacheContent{
		Ts:     time.Now(),
		Ttl:    time.Duration(firstSection.Header().Ttl),
		Answer: msg.Answer,
		Ns:     msg.Ns,
		Extra:  msg.Extra,
	}, 0)
}

func (cache *Cache) SetFromRR(rr dns.RR) {
	req := dns.Msg{
		Question: []dns.Question{
			{
				Name:  rr.Header().Name,
				Qtype: rr.Header().Rrtype,
			},
		},
	}
	msg := dns.Msg{
		Answer: []dns.RR{rr},
	}

	cache.Set(&req, &msg)
}

func keying(req *dns.Msg) string {
	key := ""
	for _, q := range req.Question {
		key += fmt.Sprintf("%s:%d,", q.Name, q.Qtype)
	}
	return key
}

func getFirstAvailableSection(msg *dns.Msg) dns.RR {
	if len(msg.Answer) > 0 {
		return msg.Answer[0]
	}

	if len(msg.Ns) > 0 {
		return msg.Ns[0]
	}

	return msg.Extra[0]
}
