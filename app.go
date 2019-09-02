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

func setupAppContainer() *dig.Container {
	var err error

	container := dig.New()
	{
		if err = container.Provide(config.New); err != nil {
			log.Err(err.Error())
		}

		if err = container.Provide(ssh.NewClientPool); err != nil {
			log.Err(err.Error())
		}

		if err = container.Provide(proxy.New); err != nil {
			log.Err(err.Error())
		}
	}

	if err != nil {
		os.Exit(1)
	}
	return container
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
