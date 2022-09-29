package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/fudanchii/ssh2dns/config"
	"github.com/fudanchii/ssh2dns/log"
	"golang.org/x/crypto/ssh"
)

type Reconnector interface {
	Reconnect() *Client
}

type Client struct {
	*ssh.Client
	Reconnector
}

func (client *Client) Drop() {
	if client.Client == nil {
		return
	}

	err := client.Close()
	if err != nil {
		log.Err(err.Error())
	}
}

type ClientPool struct {
	reconnect     chan string
	clientChannel chan *Client
	config        *config.AppConfig
}

func NewClientPool(cfg *config.AppConfig) *ClientPool {
	cp := &ClientPool{
		reconnect:     make(chan string, cfg.WorkerNum()+1),
		clientChannel: make(chan *Client, 1),
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

	for state := range cp.reconnect {
		client, err := ssh.Dial("tcp", cp.config.RemoteAddr(), &ssh.ClientConfig{
			User:            cp.config.RemoteUser(),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: cp.safeHostKeyCallback(),
		})
		if err != nil {
			if state == "init" {
				log.Fatal(err.Error())
			} else {
				log.Err(err.Error())
				log.Info("ssh: will reconnect in the next 5s")
				go func() {
					time.Sleep(5 * time.Second)
					log.Info("ssh: reconnecting...")
					cp.reconnect <- "reconnect"
				}()
			}
			if client != nil {
				client.Close()
			}
		} else {
			cp.clientChannel <- &Client{client, cp}
			log.Info("connected to " + cp.config.RemoteAddr())
		}
	}
}

func (cp *ClientPool) Connect() *Client {
	cp.reconnect <- "init"
	return <-cp.clientChannel
}

func (cp *ClientPool) Reconnect() *Client {
	cp.reconnect <- "reconnect"
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
		log.Err("Will skip remote host verification, this might harmful!")

		/* #nosec G106 */
		return ssh.InsecureIgnoreHostKey()
	}

	// HostKey is in known_host format
	if hk, err = ioutil.ReadFile(cp.config.HostKey()); err == nil {
		var pkps []ssh.HostKeyCallback
		for {
			marker, hosts, pk, _, hk, err = ssh.ParseKnownHosts(hk)
			if err == io.EOF && len(pkps) > 0 {
				return MultiHostKeys(pkps)
			}

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
				if host == cp.config.RemoteAddr() ||
					(host+":22") == cp.config.RemoteAddr() {
					if marker == "revoked" {
						err = fmt.Errorf(
							"found valid key for %s, but the key has been revoked",
							cp.config.RemoteAddr(),
						)
						goto bailOut
					}
					log.Info("Found valid host key for " + cp.config.RemoteAddr())
					log.Info("fingerprint: " + ssh.FingerprintSHA256(pk))
					pkps = append(pkps, ssh.FixedHostKey(pk))
				}
			}
		}
	}
bailOut:
	return func(host string, remote net.Addr, p ssh.PublicKey) error {
		return err
	}
}

func MultiHostKeys(pkps []ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(host string, remote net.Addr, p ssh.PublicKey) error {
		var err error
		for _, pkp := range pkps {
			if err = pkp(host, remote, p); err == nil {
				return nil
			}
		}
		return err
	}
}
