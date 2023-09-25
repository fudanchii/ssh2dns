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
// See ssh2dns -help for available options.

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
