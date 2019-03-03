package ssh

import (
	"io/ioutil"
	"log"

	"golang.org/x/crypto/ssh"
)

var (
	reconnect     = make(chan bool, 1)
	clientChannel = make(chan *ssh.Client, 1)
)

func Connect(addr string) {
	pk, err := ioutil.ReadFile(privkeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}

	for {
		if _, ok := <-reconnect; !ok {
			close(sshClientChannel)
			return
		}
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            remoteUser,
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
			logInfo("connected to " + addr)
		}
	}
}

func Reconnect() *ssh.Client {
	reconnect <- true
	<-clientChannel
}

func safeHostKeyCallback() ssh.HostKeyCallback {
	var (
		hk  []byte
		err error
		pk  ssh.PublicKey
	)
	if hostKey == "" {
		logErr("no hostKey specified, will skip remote host verification, this might harmful!")
		return ssh.InsecureIgnoreHostKey()
	}
	if hk, err = ioutil.ReadFile(hostKey); err == nil {
		if pk, err = ssh.ParsePublicKey(hk); err != nil {
			goto bailOut
		}
		return ssh.FixedHostKey(pk)
	}
bailOut:
	logErr("cannot read given hostKey: " + hostKey + ", " + err.Error())
	logErr("will skip remote host verification, this might harmful!")
	return ssh.InsecureIgnoreHostKey()
}
