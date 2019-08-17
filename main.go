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
// 		$ socks5dns -s example.com:22 -b localhost:53 -r /etc/socks5dns/resolv.txt
//
// Options:
//		-b=<127.0.0.1:53>       Bind to this host and port, default to 127.0.0.1:53
//		-c                      Enable caching
//		-i=<$HOME/.ssh/id_rsa>  Specify identity file to use when connecting to ssh server
//		-r=<./resolv.conf>      Specify a file for list of DNS to use, default to ./resolv.conf
//		-s=<127.0.0.1:22>       Connect to this ssh server, default to 127.0.0.1:22
//		-u=<$USER>              Specify user to connect with ssh server
//		-t=<30>                 Duration before connection timeout, in second. Default to 30 seconds.
//		-dns=<8.8.8.8:53>       Remote DNS server to connect to, target server should accept TCP connection, default to 8.8.8.8:53
//
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fudanchii/socks5dns/log"
	"github.com/fudanchii/socks5dns/proxy"
	"github.com/miekg/dns"

	. "github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/ssh"
)

var (
	shutdownSignal = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
}

func main() {
	log.Info("Starting...")

	go ssh.StartClientPool(Config.RemoteAddr)

	dns.HandleFunc(".", proxy.Handler)

	go func() {
		proxy.Wait()

		log.Info("Listening...")
		srv := &dns.Server{Addr: Config.BindAddr, Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Err(err.Error())
		}
	}()

	<-shutdownSignal
}
