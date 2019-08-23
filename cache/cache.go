package cache

import (
	"time"

	"github.com/fudanchii/socks5dns/config"

	"github.com/allegro/bigcache"
	"github.com/miekg/dns"
)

type Cache struct {
	bc     *bigcache.BigCache
	config *config.AppConfig
}

func New(cfg *config.AppConfig) *Cache {
	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(10 * time.Minute))
	return &Cache{cache, cfg}
}

func (cache *Cache) Get(msg *dns.Msg) (*dns.Msg, bool) {
	if !cache.config.UseCache() {
		return nil, false
	}

	msg.Answer = []dns.RR{}
	for _, question := range msg.Question {
		cacheval, err := cache.bc.Get(keying(question.Name, question.Qtype))
		if err != nil {
			return nil, false
		}

		rr, err := dns.NewRR(string(cacheval))
		if err != nil {
			return nil, false
		}

		msg.Answer = append(msg.Answer, rr)
	}

	return msg, true
}

func (cache *Cache) Set(msg *dns.Msg) {
	if !cache.config.UseCache() {
		return
	}

	for _, answer := range msg.Answer {
		header := answer.Header()
		cache.bc.Set(keying(header.Name, header.Rrtype), []byte(answer.String()))
	}
}

func keying(name string, ty uint16) string {
	return dns.TypeToString[ty] + ":" + name
}
