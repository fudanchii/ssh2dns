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
//		-d                      Enable debug message
//		-i=<$HOME/.ssh/id_rsa>  Specify identity file to use when connecting to ssh server
//		-m=<512>                Set maximum number of cache entries, default to 512
//		-r=<./resolv.conf>      Specify a file for list of DNS to use, default to ./resolv.conf
//		-s=<127.0.0.1:22>       Connect to this ssh server, default to 127.0.0.1:22
//		-u=<$USER>              Specify user to connect with ssh server
//
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/fudanchii/socks5dns/config"
	"github.com/fudanchii/socks5dns/proxy"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

var (
	shutdownSignal = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGTERM)
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UTC().UnixNano())

	go ssh.Connect(Config.RemoteAddr)

	dns.HandleFunc(".", proxy.Handler)

	go func() {
		srv := &dns.Server{Addr: Config.BindAddr, Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			logErr(err.Error())
		}
	}()

	select {
	case <-shutdownSignal:
		return
	}
}

func logErr(msg string) {
	fmt.Printf("[!] %s\n", msg)
}
func logInfo(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func logRaw(label string, msg interface{}) {
	fmt.Printf("[*] <%s> %q\n", label, msg)
}
