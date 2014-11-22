package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type lookupRequest struct {
	Cconn      *net.UDPConn
	Data       []byte
	DNS        string
	SourceAddr *net.UDPAddr
}

type cacheEntry struct {
	Data      []byte
	CreatedAt time.Time
}

const (
	cacheTTL = 7200 // second
)

var (
	bindAddr   string
	socksAddr  string
	resolvFile string
	userSet    string
	maxEntry   int
	debug      bool
	cache      bool
)

var (
	cacheStorage   = make(map[string]cacheEntry)
	cacheMutex     = new(sync.Mutex)
	shutdownSignal = make(chan os.Signal, 1)
)

func init() {
	flag.StringVar(&bindAddr, "b", "127.0.0.1:53", "Bind to address, default to localhost:53")
	flag.StringVar(&socksAddr, "s", "127.0.0.1:8080", "Use this SOCKS connection, default to localhost:8080")
	flag.StringVar(&resolvFile, "r", "./resolv.conf", "Use dns listed in this file, default to ./resolv.conf")
	flag.StringVar(&userSet, "u", "", "Set uid to this user")
	flag.IntVar(&maxEntry, "m", 512, "Set maximum number of entries for DNS cache")
	flag.BoolVar(&debug, "d", false, "Set debug mode")
	flag.BoolVar(&cache, "c", false, "Turn on query caching")

	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGTERM)

	go func() {
		hup := make(chan os.Signal, 1)
		usr1 := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		signal.Notify(usr1, syscall.SIGUSR1)
		for {
			select {
			case <-hup:
				if !cache {
					continue
				}
				cacheMutex.Lock()
				logInfo(fmt.Sprintf("current DNS cache: %d entries", len(cacheStorage)))
				cacheMutex.Unlock()
			case <-usr1:
				debug = !debug
				logInfo(fmt.Sprintf("debug: %q", debug))
			}
		}
	}()
}

func main() {
	flag.Parse()
	rand.Seed(666)

	// open resolver file, create dns list
	DNSlist := readResolvConf(resolvFile)

	// bind to dns port and wait
	bindDNS(bindAddr, socksAddr, DNSlist)
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

func bindDNS(addr, socksaddr string, list []string) {
	var wg sync.WaitGroup
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logErr(err.Error())
		return
	}
	L, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logErr(err.Error())
		return
	}
	defer L.Close()

	if err = setPrivilege(userSet); err != nil {
		logErr("set privilege: " + err.Error())
		return
	}

	logInfo("start accepting connection...")

	reqchan := make(chan *lookupRequest, 1024)
	go func(c *net.UDPConn, dlist []string) {
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
	}(L, list)

	for {
		select {
		case <-shutdownSignal:
			logInfo("Shutting down...")
			wg.Wait()
			close(reqchan)
			logInfo("Bye!")
			return
		case dnsreq, ok := <-reqchan:
			if !ok {
				return
			}
			wg.Add(1)
			go func(req *lookupRequest) {
				defer wg.Done()
				if sendFromCache(req.Cconn, req.Data, req.SourceAddr) {
					logInfo("cache HIT")
					return
				}
				connectSOCKS(socksaddr, req)
				logInfo("cache MISS")
			}(dnsreq)
		}
	}
}

func connectSOCKS(addr string, request *lookupRequest) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logErr("socks server: " + err.Error())
		return
	}
	defer conn.Close()

	// First bow
	conn.Write([]byte{0x05, 0x01, 0x00})

	rsp := make([]byte, 512)
	rlen, err := conn.Read(rsp)
	if err != nil && err != io.EOF {
		logErr("handshake response: " + err.Error())
		return
	}
	logRaw("handshake", rsp[:rlen])

	// Send SOCKS header, connect to this IP on this port
	bbuff := new(bytes.Buffer)
	bbuff.Write([]byte{0x05, 0x01, 0x00, 0x01})
	bbuff.Write(net.ParseIP(request.DNS).To4())
	bbuff.Write([]byte{0x00, 53})

	logRaw("header", bbuff.Bytes()[:10])
	_, err = conn.Write(bbuff.Bytes()[:10])
	if err != nil {
		logErr("send header: " + err.Error())
		return
	}

	rsp = make([]byte, 512)
	rlen, err = conn.Read(rsp)
	if err != nil && err != io.EOF {
		logErr("header response: " + err.Error())
		return
	}
	logRaw("rsp", rsp[:rlen])

	// Need to prepend query length since we get this from UDP
	// (TCP doesn't need this)
	sbuff := new(bytes.Buffer)
	if err = binary.Write(sbuff, binary.BigEndian, int16(len(request.Data))); err != nil {
		logErr("packet length: " + err.Error())
		return
	}
	sbuff.Write(request.Data)

	logRaw("query", sbuff.Bytes())
	_, err = conn.Write(sbuff.Bytes())
	if err != nil {
		logErr("send query: " + err.Error())
		return
	}

	rsp = make([]byte, 65536)
	rlen, err = conn.Read(rsp)
	if err != nil && err != io.EOF {
		logErr("query response: " + err.Error())
		return
	}

	// Send back to UDP, do not want the length
	logRaw("rsp", rsp[2:rlen])
	_, err = request.Cconn.WriteToUDP(rsp[2:rlen], request.SourceAddr)
	if err != nil {
		logErr("forward response: " + err.Error())
	}

	if cache && queryHasAnswer(rsp[2:rlen]) {
		setCache(request.Data, rsp[2:rlen])
	} else if cache {
		logErr("response not cached")
	}
}

func setCache(q, data []byte) {
	cacheMutex.Lock()

	// only match q from the 13th character
	cacheStorage[string(q[13:])] = cacheEntry{
		Data:      data[2:],
		CreatedAt: time.Now(),
	}

	cacheMutex.Unlock()
}

func sendFromCache(c *net.UDPConn, q []byte, target *net.UDPAddr) bool {
	cacheMutex.Lock()
	entry, exists := cacheStorage[string(q[13:])]
	cacheMutex.Unlock()

	if cache && exists && (time.Since(entry.CreatedAt) <= cacheTTL*time.Second) {
		answer := new(bytes.Buffer)
		answer.Write(q[:2])
		answer.Write(entry.Data)
		c.WriteToUDP(answer.Bytes(), target)
		logRaw("rsp", answer.Bytes())
		return true
	}

	cacheMutex.Lock()
	if exists && (time.Since(entry.CreatedAt) > cacheTTL*time.Second) {
		delete(cacheStorage, string(q[13:]))
	}

	lc := len(cacheStorage)
	if lc > maxEntry {
		i := 0
		for k := range cacheStorage {
			delete(cacheStorage, k)
			if i > (maxEntry / 2) {
				break
			}
			i++
		}
		logErr(fmt.Sprintf("Cache entries were too many: %d", lc))
	}
	cacheMutex.Unlock()
	return false
}

func setPrivilege(tUser string) error {
	if len(tUser) == 0 {
		return nil
	}

	current, err := user.Current()
	if err != nil {
		return err
	}

	if current.Uid != "0" {
		logInfo("not a root, will keep running as " + current.Username)
		return nil
	}

	ug := strings.SplitN(tUser, ":", 2)
	nUser, err := user.Lookup(ug[0])
	if err != nil {
		return err
	}
	uid, err := strconv.ParseInt(nUser.Uid, 10, 32)
	if err != nil {
		return err
	}
	err = syscall.Setuid(int(uid))
	return err
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
