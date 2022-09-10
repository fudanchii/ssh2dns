package cache

import (
	"fmt"

	"github.com/fudanchii/ssh2dns/config"
	"github.com/fudanchii/ssh2dns/log"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
)

type Cache struct {
	rc     *ristretto.Cache
	config *config.AppConfig
}

type dnsCacheContent struct {
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
	msg.Answer = actualval.Answer
	msg.Ns = actualval.Ns
	msg.Extra = actualval.Extra

	return msg, true
}

func (cache *Cache) Set(req *dns.Msg, msg *dns.Msg) {
	cache.rc.Set(keying(req), dnsCacheContent{
		Answer: msg.Answer,
		Ns:     msg.Ns,
		Extra:  msg.Extra,
	}, 0)
}

func keying(req *dns.Msg) string {
	key := ""
	for _, q := range req.Question {
		key += fmt.Sprintf("%s:%d,", q.Name, q.Qtype)
	}
	return key
}
