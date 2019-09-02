package ssh

import (
	"io/ioutil"
	"log"

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

	for range cp.reconnect {
		client, err := ssh.Dial("tcp", cp.config.RemoteAddr(), &ssh.ClientConfig{
			User:            cp.config.RemoteUser(),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: cp.safeHostKeyCallback(),
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
		hk  []byte
		err error
		pk  ssh.PublicKey
	)
	if cp.config.HostKey() == "" {
		l.Err("no hostKey specified, will skip remote host verification, this might harmful!")

		/* #nosec G106 */
		return ssh.InsecureIgnoreHostKey()
	}
	if hk, err = ioutil.ReadFile(cp.config.HostKey()); err == nil {
		if pk, err = ssh.ParsePublicKey(hk); err != nil {
			goto bailOut
		}
		return ssh.FixedHostKey(pk)
	}
bailOut:
	l.Err("cannot read given hostKey: " + cp.config.HostKey() + ", " + err.Error())
	l.Err("will skip remote host verification, this might harmful!")

	/* #nosec G106 */
	return ssh.InsecureIgnoreHostKey()
}
