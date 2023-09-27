package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fudanchii/ssh2dns/internal/config"
	"github.com/fudanchii/ssh2dns/internal/errors"
	"github.com/fudanchii/ssh2dns/internal/log"
	"github.com/fudanchii/ssh2dns/internal/recdns"
	"github.com/jackc/puddle/v2"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	*ssh.Client
}

func (cli *Client) DialTCPWithContext(ctx context.Context, addr string) (net.Conn, error) {
	var (
		errResultChannel chan error    = make(chan error, 1)
		connChannel      chan net.Conn = make(chan net.Conn, 1)
	)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	go func() {
		conn, err := cli.Dial("tcp", addr)
		if err != nil {
			errResultChannel <- err
			return
		}
		connChannel <- conn
	}()

	select {
	case <-ctx.Done():
		return nil, errors.ConnectionTimeout{}
	case err := <-errResultChannel:
		return nil, err
	case conn := <-connChannel:
		return conn, nil
	}
}

func createNewClient(cfg *config.AppConfig, signer ssh.Signer) puddle.Constructor[recdns.DNSClient] {
	return func(_ context.Context) (recdns.DNSClient, error) {
		client, err := ssh.Dial("tcp", cfg.RemoteAddr(), &ssh.ClientConfig{
			User:            cfg.RemoteUser(),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: safeHostKeyCallback(cfg),
			HostKeyAlgorithms: []string{
				"ssh-ed25519",
				"ecdsa-sha2-nistp521",
				"ecdsa-sha2-nistp384",
				"ecdsa-sha2-nistp256",
				"ssh-rsa",
			},
		})
		if err != nil {
			return nil, err
		}

		log.Info("connected to " + cfg.RemoteAddr())
		return &Client{client}, nil
	}
}

func dropClient(cli recdns.DNSClient) {
	if cli != nil {
		cli.Close()
		cli = nil
	}
}

func newSigner(pkfile string) (ssh.Signer, error) {
	pk, err := os.ReadFile(pkfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

type ClientPool struct {
	pool   *puddle.Pool[recdns.DNSClient]
	config *config.AppConfig
	signer ssh.Signer
}

func NewClientPool(cfg *config.AppConfig) (recdns.DNSClientPool, error) {
	signer, err := newSigner(cfg.PrivKeyFile())
	if err != nil {
		return nil, err
	}

	ppool, err := puddle.NewPool(&puddle.Config[recdns.DNSClient]{
		Constructor: createNewClient(cfg, signer),
		Destructor:  dropClient,
		MaxSize:     int32(cfg.WorkerNum()),
	})

	if err != nil {
		return nil, err
	}

	initCtx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	// try connecting first, bailout if we can't connect at init
	cli, err := ppool.Acquire(initCtx)
	if err != nil {
		return nil, err
	}
	cli.Release()

	return &ClientPool{
		pool:   ppool,
		signer: signer,
		config: cfg,
	}, nil
}

func (cp *ClientPool) Acquire(ctx context.Context) (recdns.PoolItemWrapper[recdns.DNSClient], error) {
	return cp.pool.Acquire(ctx)
}

func (cp *ClientPool) Close() {
	cp.pool.Close()
}

func safeHostKeyCallback(cfg *config.AppConfig) ssh.HostKeyCallback {
	var (
		err    error
		hk     []byte
		marker string
		hosts  []string
		pk     ssh.PublicKey
	)

	if cfg.DoNotVerifyHost() {
		log.Err("Will skip remote host verification, this might harmful!")

		/* #nosec G106 */
		return ssh.InsecureIgnoreHostKey()
	}

	// HostKey is in known_host format
	if hk, err = os.ReadFile(cfg.HostKey()); err == nil {
		var pkps []ssh.HostKeyCallback
		for {
			marker, hosts, pk, _, hk, err = ssh.ParseKnownHosts(hk)
			if err == io.EOF && len(pkps) > 0 {
				return MultiHostKeys(pkps)
			}

			if err == io.EOF {
				err = fmt.Errorf("No valid key found for host: " + cfg.RemoteAddr())
				goto bailOut
			}

			if err != nil {
				goto bailOut
			}

			for _, host := range hosts {
				host = strings.ReplaceAll(host, "[", "")
				host = strings.ReplaceAll(host, "]", "")
				if host == cfg.RemoteAddr() ||
					(host+":22") == cfg.RemoteAddr() {
					if marker == "revoked" {
						err = fmt.Errorf(
							"found valid key for %s, but the key has been revoked",
							cfg.RemoteAddr(),
						)
						goto bailOut
					}
					log.Info("fingerprint: " + pk.Type() + " " + ssh.FingerprintSHA256(pk))
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
