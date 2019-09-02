package main

import (
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
	container := dig.New()
	container.Provide(config.New)
	container.Provide(ssh.NewClientPool)
	container.Provide(proxy.New)
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
