// ssh2dns relays DNS request via ssh tunnel proxy
// it works by connecting to specified remote ssh server
// and bind to local address. It will then forward any
// dns request via ssh connection to the DNS server,
// either to the default 8.8.8.8, or recursively from the root NS.
//
// ssh2dns also provides simple caching for the nameserver
// query result.
//
// Usage examples:
//
//	$ ssh2dns -s example.com:22 -b localhost:53
//
// Options:
//
//	-b=<127.0.0.1:53>       Bind to this host and port. Default to 127.0.0.1:53.
//	-c                      Enable caching.
//	-i=<$HOME/.ssh/id_rsa>  Specify identity file to use when connecting to ssh server.
//	-s=<127.0.0.1:22>       Connect to this ssh server. Default to 127.0.0.1:22.
//	-u=<$USER>              Specify user to connect with ssh server.
//	-t=<30>                 Duration before connection timeout, in second. Default to 30 seconds.
//	-dns=<8.8.8.8:53>       Remote DNS server to connect to,
//	                        target server should accept TCP connection. Default to 8.8.8.8:53.
//	-w=<# of CPU>           Number of workers to run. Default to the number of CPU.
//	-h=<>                   Specify hostkey to verify whether ssh server is trusted or not.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fudanchii/ssh2dns/internal/log"
)

func main() {
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	log.Info("Starting...")

	if err := setupAppContainer().Invoke(appStart(shutdownSignal)); err != nil {
		log.Err(err.Error())
		os.Exit(1)
	}

	fmt.Println("bye!")
}
