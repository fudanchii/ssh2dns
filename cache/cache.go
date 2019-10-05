package cache

import (
	"github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/log"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
)

type Cache struct {
	rc     *ristretto.Cache
	config *config.AppConfig
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
	msg.Answer = []dns.RR{}
	for _, question := range msg.Question {
		cacheval, found := cache.rc.Get(keying(question.Name, question.Qtype))
		if !found {
			return nil, found
		}

		rr, err := dns.NewRR(string(cacheval.([]byte)))
		if err != nil {
			return nil, false
		}

		msg.Answer = append(msg.Answer, rr)
	}

	return msg, true
}

func (cache *Cache) Set(msg *dns.Msg) {
	for _, answer := range msg.Answer {
		header := answer.Header()
		cache.rc.Set(keying(header.Name, header.Rrtype), []byte(answer.String()), 1)
	}
}

func keying(name string, ty uint16) string {
	return dns.TypeToString[ty] + ":" + name
}
