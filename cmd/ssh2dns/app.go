package main

import (
	"os"

	"github.com/fudanchii/ssh2dns/internal/cache"
	"github.com/fudanchii/ssh2dns/internal/config"
	"github.com/fudanchii/ssh2dns/internal/log"
	"github.com/fudanchii/ssh2dns/internal/proxy"
	"github.com/fudanchii/ssh2dns/internal/ssh"
	"go.uber.org/dig"
)

type Dependencies struct {
	dig.In

	Config     *config.AppConfig
	ClientPool *ssh.ClientPool
	DNSProxy   *proxy.Proxy
}

type container struct {
	*dig.Container
}

func (c *container) provide(cons ...interface{}) *dig.Container {
	for _, constructor := range cons {
		if err := c.Provide(constructor); err != nil {
			log.Err(err.Error())
			os.Exit(1)
		}
	}

	return c.Container
}

func setupAppContainer() *dig.Container {
	return (&container{dig.New()}).provide(
		config.New,
		cache.New,
		ssh.NewClientPool,
		proxy.New,
	)
}

func appStart(signal chan os.Signal) func(Dependencies) {
	return func(dep Dependencies) {
		go func(dep *Dependencies) {
			log.Info("Listening...")
			if err := dep.DNSProxy.ListenAndServe(); err != nil {
				log.Err(err.Error())
			}
		}(&dep)

		defer dep.DNSProxy.Shutdown()

		<-signal
	}
}
