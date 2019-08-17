package ssh

import (
	"io/ioutil"
	"log"

	. "github.com/fudanchii/socks5dns/config"
	l "github.com/fudanchii/socks5dns/log"
	"golang.org/x/crypto/ssh"
)

var (
	reconnect     = make(chan bool, Config.WorkerNum+1)
	clientChannel = make(chan *ssh.Client, 1)
)

func StartClientPool(addr string) {
	pk, err := ioutil.ReadFile(Config.PrivkeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}

	for range reconnect {
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            Config.RemoteUser,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: safeHostKeyCallback(),
		})
		if err != nil {
			log.Fatal(err.Error())
			if client != nil {
				client.Close()
			}
		} else {
			clientChannel <- client
			l.Info("connected to " + addr)
		}
	}
}

func Connect() *ssh.Client {
	reconnect <- true
	return <-clientChannel
}

func safeHostKeyCallback() ssh.HostKeyCallback {
	var (
		hk  []byte
		err error
		pk  ssh.PublicKey
	)
	if Config.HostKey == "" {
		l.Err("no hostKey specified, will skip remote host verification, this might harmful!")
		return ssh.InsecureIgnoreHostKey()
	}
	if hk, err = ioutil.ReadFile(Config.HostKey); err == nil {
		if pk, err = ssh.ParsePublicKey(hk); err != nil {
			goto bailOut
		}
		return ssh.FixedHostKey(pk)
	}
bailOut:
	l.Err("cannot read given hostKey: " + Config.HostKey + ", " + err.Error())
	l.Err("will skip remote host verification, this might harmful!")
	return ssh.InsecureIgnoreHostKey()
}
