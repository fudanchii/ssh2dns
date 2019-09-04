package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/fudanchii/socks5dns/config"
	l "github.com/fudanchii/socks5dns/log"
	"golang.org/x/crypto/ssh"
)

type ClientPool struct {
	reconnect     chan bool
	clientChannel chan *ssh.Client
	config        *config.AppConfig
}

func NewClientPool(cfg *config.AppConfig) *ClientPool {
	cp := &ClientPool{
		reconnect:     make(chan bool, cfg.WorkerNum()+1),
		clientChannel: make(chan *ssh.Client, 1),
		config:        cfg,
	}
	go cp.StartClientPool()
	return cp
}

func (cp *ClientPool) StartClientPool() {
	pk, err := ioutil.ReadFile(cp.config.PrivKeyFile())
	if err != nil {
		log.Fatal(err.Error())
	}

	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}

	hostKeyCB := cp.safeHostKeyCallback()
	for range cp.reconnect {
		client, err := ssh.Dial("tcp", cp.config.RemoteAddr(), &ssh.ClientConfig{
			User:            cp.config.RemoteUser(),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeyCB,
		})
		if err != nil {
			log.Fatal(err.Error())
			if client != nil {
				client.Close()
			}
		} else {
			cp.clientChannel <- client
			l.Info("connected to " + cp.config.RemoteAddr())
		}
	}
}

func (cp *ClientPool) Connect() *ssh.Client {
	cp.reconnect <- true
	return <-cp.clientChannel
}

func (cp *ClientPool) safeHostKeyCallback() ssh.HostKeyCallback {
	var (
		err    error
		hk     []byte
		marker string
		hosts  []string
		pk     ssh.PublicKey
	)

	if cp.config.DoNotVerifyHost() {
		l.Err("Will skip remote host verification, this might harmful!")

		/* #nosec G106 */
		return ssh.InsecureIgnoreHostKey()
	}

	// HostKey is in known_host format
	if hk, err = ioutil.ReadFile(cp.config.HostKey()); err == nil {
		for {
			marker, hosts, pk, _, hk, err = ssh.ParseKnownHosts(hk)
			if err == io.EOF {
				err = fmt.Errorf("No valid key found for host: " + cp.config.RemoteAddr())
				goto bailOut
			}

			if err != nil {
				goto bailOut
			}

			for _, host := range hosts {
				host = strings.ReplaceAll(host, "[", "")
				host = strings.ReplaceAll(host, "]", "")
				if host == cp.config.RemoteAddr() {
					if marker == "revoked" {
						err = fmt.Errorf(
							"found valid key for %s, but the key has been revoked",
							cp.config.RemoteAddr(),
						)
						goto bailOut
					}
					l.Info("Found valid host key for " + cp.config.RemoteAddr())
					l.Info("fingerprint: " + ssh.FingerprintSHA256(pk))
					return ssh.FixedHostKey(pk)
				}
			}
		}
	}
bailOut:
	return func(host string, remote net.Addr, p ssh.PublicKey) error {
		return err
	}
}
