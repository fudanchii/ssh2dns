package config

import (
	"flag"
	"os"
	"path"
	"runtime"
)

type AppConfig struct {
	BindAddr    string
	RemoteAddr  string
	HostKey     string
	RemoteUser  string
	PrivkeyFile string
	ConnTimeout int
	WorkerNum   int
	UseCache    bool
}

var Config = AppConfig{}

func init() {
	defrsa := path.Join(os.Getenv("HOME"), ".ssh/id_rsa")
	flag.StringVar(&Config.BindAddr, "b", "127.0.0.1:53", "Bind to this host and port, default to 127.0.0.1:53")
	flag.StringVar(&Config.PrivkeyFile, "i", defrsa, "Specify identity file to use when connecting to ssh server")
	flag.StringVar(&Config.RemoteAddr, "s", "127.0.0.1:22", "Connect to this ssh server, default to 127.0.0.1:22")
	flag.StringVar(&Config.RemoteUser, "u", os.Getenv("USER"), "Specify user to connect with ssh server")
	flag.StringVar(&Config.HostKey, "h", "", "Specify hostkey to use with ssh server")
	flag.IntVar(&Config.ConnTimeout, "t", 30, "Set timeout for net dial, default to 30 seconds")
	flag.IntVar(&Config.WorkerNum, "w", runtime.NumCPU(), "Set the number of worker to run as ssh client, default to number of cpu")
	flag.BoolVar(&Config.UseCache, "c", false, "Use cache, default to false")
}
