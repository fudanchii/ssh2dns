// Socks5dns relays DNS request via ssh tunnel proxy
// it works by connecting to specified remote ssh server
// and bind to local address. It will then forward any
// dns request via ssh connection to the DNS server, randomly-
// chosen from the specified list.
//
// Socks5dns also provides simple caching for the nameserver
// query result.
//
// Usage examples:
// 		$ socks5dns -s example.com:22 -b localhost:53 -r /etc/socks5dns/resolv.txt
//
// Options:
//		-b=<127.0.0.1:53>       Bind to this host and port, default to 127.0.0.1:53
//		-c                      Enable caching
//		-d                      Enable debug message
//		-i=<$HOME/.ssh/id_rsa>  Specify identity file to use when connecting to ssh server
//		-m=<512>                Set maximum number of cache entries, default to 512
//		-r=<./resolv.conf>      Specify a file for list of DNS to use, default to ./resolv.conf
//		-s=<127.0.0.1:22>       Connect to this ssh server, default to 127.0.0.1:22
//		-u=<$USER>              Specify user to connect with ssh server
//
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type handler interface {
	Accept(*lookupRequest)
	Close()
}

// lookupRequest holds information for each request,
// including source address, payload data and
// DNS server being used.
type lookupRequest struct {
	Cconn      *net.UDPConn
	Data       []byte
	DNS        string
	SourceAddr *net.UDPAddr
}

// cacheEntry stores answer payload and its timestamp
type cacheEntry struct {
	Data      []byte
	CreatedAt time.Time
}

// cacheStorage maps query to its cached answer.
type cacheStorage struct {
	Entries map[string]cacheEntry
	Mutex   *sync.Mutex
}

// dnsServer holds local dns server listener.
type dnsServer struct {
	RequestChannel chan *lookupRequest
	Listener       net.Conn
}

// proxyHandler handle dns request and relay them
// via proxy connection.
type proxyHandler struct {
	Client *ssh.Client
}

const (
	cacheTTL = 7200 // second
)

var (
	bindAddr    string
	remoteAddr  string
	remoteUser  string
	resolvFile  string
	privkeyFile string
	maxEntry    int
	debug       bool
	useCache    bool
)

var (
	cache = cacheStorage{
		Entries: make(map[string]cacheEntry),
		Mutex:   new(sync.Mutex),
	}
	shutdownSignal = make(chan os.Signal, 1)
)

func init() {
	defrsa := path.Join(os.Getenv("HOME"), ".ssh/id_rsa")
	flag.StringVar(&bindAddr, "b", "127.0.0.1:53", "Bind to this host and port, default to 127.0.0.1:53")
	flag.BoolVar(&useCache, "c", false, "Enable caching")
	flag.BoolVar(&debug, "d", false, "Enable debug message")
	flag.StringVar(&privkeyFile, "i", defrsa, "Specify identity file to use when connecting to ssh server")
	flag.IntVar(&maxEntry, "m", 512, "Set maximum number of cache entries, default to 512")
	flag.StringVar(&resolvFile, "r", "./resolv.conf", "Specify a file for list of DNS to use, default to ./resolv.conf")
	flag.StringVar(&remoteAddr, "s", "127.0.0.1:22", "Connect to this ssh server, default to 127.0.0.1:22")
	flag.StringVar(&remoteUser, "u", os.Getenv("USER"), "Specify user to connect with ssh server")

	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGTERM)

	go func() {
		hup := make(chan os.Signal, 1)
		usr1 := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		signal.Notify(usr1, syscall.SIGUSR1)
		for {
			select {
			case <-hup:
				if !useCache {
					continue
				}
				cache.Mutex.Lock()
				logInfo(fmt.Sprintf("current DNS cache: %d entries", len(cache.Entries)))
				cache.Mutex.Unlock()
			case <-usr1:
				debug = !debug
				logInfo(fmt.Sprintf("debug: %v", debug))
			}
		}
	}()
}

func main() {
	flag.Parse()
	rand.Seed(666)

	// open resolver file, create dns list
	DNSlist := readResolvConf(resolvFile)

	// Create proxy
	dns := bindDNS(bindAddr, DNSlist)
	dns.Serve(viaProxy(remoteAddr))
}

func readResolvConf(rfile string) []string {
	content, err := ioutil.ReadFile(rfile)
	if err != nil {
		logErr("can't read resolver list: " + err.Error())
		logErr("will use 8.8.8.8 and 8.8.4.4 as default resolver")
		return []string{"8.8.8.8", "8.8.4.4"}
	}
	content = bytes.TrimSpace(content)
	return strings.Split(string(content), "\n")
}

func bindDNS(addr string, list []string) *dnsServer {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err.Error())
	}
	L, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err.Error())
	}

	logInfo("start accepting connection...")

	reqchan := make(chan *lookupRequest, 1024)
	go func(c *net.UDPConn, dlist []string, rqch chan *lookupRequest) {
		for {
			rdata := make([]byte, 4096)
			rlen, rAddr, err := c.ReadFromUDP(rdata)
			if err != nil {
				logErr("can not read request: " + err.Error())
				return
			}
			logRaw("request", rdata[:rlen])
			reqchan <- &lookupRequest{
				Cconn:      c,
				Data:       rdata[:rlen],
				DNS:        dlist[rand.Intn(len(dlist))],
				SourceAddr: rAddr,
			}
		}
	}(L, list, reqchan)
	return &dnsServer{
		RequestChannel: reqchan,
		Listener:       L,
	}
}

func viaProxy(rAddr string) handler {
	pk, err := ioutil.ReadFile(privkeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}
	client, err := ssh.Dial("tcp", rAddr, &ssh.ClientConfig{
		User: remoteUser,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	logInfo("connected to " + rAddr)
	return &proxyHandler{
		Client: client,
	}
}

func (ds *dnsServer) Serve(hnd handler) {
	var wg sync.WaitGroup
	defer func() {
		logInfo("Shutting down...")
		ds.Listener.Close()
		close(ds.RequestChannel)
		wg.Wait()
		hnd.Close()
		logInfo("Bye!")
	}()
	for {
		select {
		case <-shutdownSignal:
			return
		case dnsreq, ok := <-ds.RequestChannel:
			if !ok {
				return
			}
			wg.Add(1)
			go func(req *lookupRequest) {
				defer wg.Done()
				if useCache && sendFromCache(req.Cconn, req.Data, req.SourceAddr) {
					logInfo("cache HIT")
					return
				}
				hnd.Accept(req)
				logInfo("cache MISS")
			}(dnsreq)
		}
	}
}

func (ph *proxyHandler) Accept(req *lookupRequest) {
	conn, err := ph.Client.Dial("tcp", req.DNS+":53")
	if err != nil {
		logErr("can't connect to remote dns: " + err.Error())
		return
	}
	// Need to prepend query length since we get this from UDP
	// (TCP doesn't need this)
	sbuff := new(bytes.Buffer)
	if err = binary.Write(sbuff, binary.BigEndian, int16(len(req.Data))); err != nil {
		logErr("packet length: " + err.Error())
		return
	}
	sbuff.Write(req.Data)

	logRaw("query", sbuff.Bytes())
	_, err = conn.Write(sbuff.Bytes())
	if err != nil {
		logErr("send query: " + err.Error())
		return
	}

	rsp := make([]byte, 65536)
	rlen, err := conn.Read(rsp)
	if err != nil {
		logErr("query response: " + err.Error())
		return
	}

	// Send back to UDP, do not want the length
	logRaw("rsp", rsp[2:rlen])
	_, err = req.Cconn.WriteToUDP(rsp[2:rlen], req.SourceAddr)
	if err != nil {
		logErr("forward response: " + err.Error())
	}

	if useCache && queryHasAnswer(rsp[2:rlen]) {
		setCache(req.Data, rsp[2:rlen])
	} else if useCache {
		logErr("response not cached")
	}
}

func (ph *proxyHandler) Close() {
	ph.Client.Conn.Close()
}

func setCache(q, data []byte) {
	cache.Mutex.Lock()

	// only match q from the 13th character
	cache.Entries[string(q[13:])] = cacheEntry{
		Data:      data[2:],
		CreatedAt: time.Now(),
	}

	cache.Mutex.Unlock()
}

// sendFromCache will check if query is already cached and send the cached
// response back to user. This function will assume useCache is true
func sendFromCache(c *net.UDPConn, q []byte, target *net.UDPAddr) bool {
	cache.Mutex.Lock()
	entry, exists := cache.Entries[string(q[13:])]
	cache.Mutex.Unlock()

	if exists && (time.Since(entry.CreatedAt) <= cacheTTL*time.Second) {
		answer := new(bytes.Buffer)
		answer.Write(q[:2])
		answer.Write(entry.Data)
		c.WriteToUDP(answer.Bytes(), target)
		logRaw("rsp", answer.Bytes())
		return true
	}

	cache.Mutex.Lock()
	if exists && (time.Since(entry.CreatedAt) > cacheTTL*time.Second) {
		delete(cache.Entries, string(q[13:]))
	}

	lc := len(cache.Entries)
	if lc > maxEntry {
		i := 0
		for k := range cache.Entries {
			delete(cache.Entries, k)
			if i > (maxEntry / 2) {
				break
			}
			i++
		}
		logErr(fmt.Sprintf("Cache entries were too many: %d", lc))
	}
	cache.Mutex.Unlock()
	return false
}

func queryHasAnswer(message []byte) bool {
	var ansRR int16

	// read from the 6th byte,
	// we just want to know if this message contains answer RR
	buff := bytes.NewReader(message[6:])
	if err := binary.Read(buff, binary.BigEndian, &ansRR); err != nil {
		logErr("can't parse answer RR number")
		return false
	}
	if ansRR < 1 {
		logErr("no answer")
		return false
	}
	return true
}

func logErr(msg string) {
	fmt.Printf("[!] %s\n", msg)
}
func logInfo(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func logRaw(label string, msg interface{}) {
	if debug {
		fmt.Printf("[*] <%s> %q\n", label, msg)
	}
}
