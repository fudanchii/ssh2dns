package config

import (
	"flag"
	"os"
	"path"
	"runtime"
)

type AppConfig struct {
	bindAddr     string
	remoteAddr   string
	hostKey      string
	remoteUser   string
	privkeyFile  string
	targetServer string
	connTimeout  int
	workerNum    int
	useCache     bool
}

func New() *AppConfig {
	var config AppConfig

	defrsa := path.Join(os.Getenv("HOME"), ".ssh/id_rsa")

	flag.StringVar(
		&config.bindAddr,
		"b", "127.0.0.1:53",
		"Bind to this host and port, default to 127.0.0.1:53",
	)
	flag.StringVar(
		&config.privkeyFile,
		"i", defrsa,
		"Specify identity file to use when connecting to ssh server",
	)
	flag.StringVar(
		&config.remoteAddr,
		"s", "127.0.0.1:22",
		"Connect to this ssh server, default to 127.0.0.1:22",
	)
	flag.StringVar(
		&config.remoteUser,
		"u", os.Getenv("USER"),
		"Specify user to connect with ssh server",
	)
	flag.StringVar(
		&config.hostKey,
		"h", "",
		"Specify hostkey to use with ssh server",
	)
	flag.StringVar(
		&config.targetServer,
		"dns", "8.8.8.8:53",
		"Remote DNS server to connect to, should accept TCP connection, default to 8.8.8.8:53",
	)
	flag.IntVar(
		&config.connTimeout,
		"t", 30,
		"Set timeout for net dial, default to 30 seconds",
	)
	flag.IntVar(
		&config.workerNum,
		"w", runtime.NumCPU(),
		"Set the number of worker to run as ssh client, default to number of cpu",
	)
	flag.BoolVar(
		&config.useCache,
		"c", false,
		"Use cache, default to false",
	)

	flag.Parse()

	return &config
}

func (c *AppConfig) BindAddr() string {
	return c.bindAddr
}

func (c *AppConfig) PrivKeyFile() string {
	return c.privkeyFile
}

func (c *AppConfig) RemoteAddr() string {
	return c.remoteAddr
}

func (c *AppConfig) RemoteUser() string {
	return c.remoteUser
}

func (c *AppConfig) HostKey() string {
	return c.hostKey
}

func (c *AppConfig) TargetServer() string {
	return c.targetServer
}

func (c *AppConfig) ConnTimeout() int {
	return c.connTimeout
}

func (c *AppConfig) WorkerNum() int {
	return c.workerNum
}

func (c *AppConfig) UseCache() bool {
	return c.useCache
}
