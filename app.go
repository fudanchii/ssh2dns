package main

import (
	"os"

	"github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/log"
	"github.com/fudanchii/socks5dns/proxy"
	"github.com/fudanchii/socks5dns/ssh"
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
		ssh.NewClientPool,
		proxy.New,
	)
}

func appStart(dep Dependencies) {
	dep.DNSProxy.Wait()

	go func(dep *Dependencies) {
		log.Info("Listening...")
		if err := dep.DNSProxy.ListenAndServe(); err != nil {
			log.Err(err.Error())
		}
	}(&dep)
}
