// Socks5dns relays DNS request via ssh tunnel proxy
// it works by connecting to specified remote ssh server
// and bind to local address. It will then forward any
// dns request via ssh connection to the DNS server, randomly-
// chosen from the specified list.
//
// Socks5dns also provides simple caching for the nameserver
// query result.
//
// Usage examples:
//      $ socks5dns -s example.com:22 -b localhost:53
//
// Options:
//      -b=<127.0.0.1:53>       Bind to this host and port. Default to 127.0.0.1:53.
//      -c                      Enable caching.
//      -i=<$HOME/.ssh/id_rsa>  Specify identity file to use when connecting to ssh server.
//      -s=<127.0.0.1:22>       Connect to this ssh server. Default to 127.0.0.1:22.
//      -u=<$USER>              Specify user to connect with ssh server.
//      -t=<30>                 Duration before connection timeout, in second. Default to 30 seconds.
//      -dns=<8.8.8.8:53>       Remote DNS server to connect to,
//                              target server should accept TCP connection. Default to 8.8.8.8:53.
//      -w=<# of CPU>           Number of workers to run. Default to the number of CPU.
//      -h=<>                   Specify hostkey to verify whether ssh server is trusted or not.
//
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fudanchii/socks5dns/log"
	"github.com/fudanchii/socks5dns/proxy"
	"github.com/miekg/dns"

	"github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/ssh"
)

func main() {
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	log.Info("Starting...")

	cfg := config.New()

	clientPool := ssh.NewClientPool(cfg)
	go clientPool.StartClientPool()

	dnsProxy := proxy.New(cfg, clientPool)
	dns.HandleFunc(".", dnsProxy.Handler)

	go func(cfg *config.AppConfig, proxy *proxy.Proxy) {
		proxy.Wait()

		log.Info("Listening...")
		srv := &dns.Server{Addr: cfg.BindAddr(), Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Err(err.Error())
		}
	}(cfg, dnsProxy)

	<-shutdownSignal
}
