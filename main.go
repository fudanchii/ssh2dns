package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
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
	CacheTTL = 7200 // second
)

var (
	bindAddr   string
	socksAddr  string
	resolvFile string
	userSet    string
	debug      bool
	cache      bool
)

var (
	cacheStorage = make(map[string]cacheEntry)
	cacheMutex   = new(sync.Mutex)
)

func init() {
	flag.StringVar(&bindAddr, "b", "127.0.0.1:53", "Bind to address, default to localhost:53")
	flag.StringVar(&socksAddr, "s", "127.0.0.1:8080", "Use this SOCKS connection, default to localhost:8080")
	flag.StringVar(&resolvFile, "r", "./resolv.conf", "Use dns listed in this file, default to ./resolv.conf")
	flag.StringVar(&userSet, "u", "", "Set uid to this user")
	flag.BoolVar(&debug, "d", false, "Set debug mode")
	flag.BoolVar(&cache, "c", false, "Turn on query caching")
}

func main() {
	flag.Parse()
	rand.Seed(666)

	// open resolver file, create dns list
	DNSlist, err := readResolvConf(resolvFile)
	if err != nil {
		log_err("can't read resolv.conf: " + err.Error())
		log_err("will use 8.8.8.8 and 8.8.4.4 as default resolver")
		DNSlist = append(DNSlist, "8.8.8.8", "8.8.4.4")
	}

	// bind to dns port and wait
	bindDNS(bindAddr, socksAddr, DNSlist)
}

func readResolvConf(rfile string) ([]string, error) {
	content, err := ioutil.ReadFile(rfile)
	content = bytes.TrimSpace(content)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(content), "\n"), nil
}

func bindDNS(addr, socksaddr string, list []string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log_err(err.Error())
		return
	}
	L, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log_err(err.Error())
		return
	}
	defer L.Close()

	if err = setPrivilege(userSet); err != nil {
		log_err("set privilege: " + err.Error())
		return
	}

	log_info("start accepting connection...")
	for {
		rdata := make([]byte, 2048)
		rlen, rAddr, err := L.ReadFromUDP(rdata)
		if err != nil {
			log_err("can not read request: " + err.Error())
			return
		}
		log_raw("request", rdata[:rlen])

		go func(c *net.UDPConn, data []byte, target *net.UDPAddr) {
			if sendFromCache(c, data, target) {
				log_raw("cache", "HIT")
				return
			}
			log_raw("cache", "MISS")
			connectSOCKS(socksaddr, &lookupRequest{
				Cconn:      c,
				Data:       data,
				DNS:        list[rand.Intn(len(list))],
				SourceAddr: target,
			})
		}(L, rdata[:rlen], rAddr)
	}
}

func connectSOCKS(addr string, request *lookupRequest) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log_err("socks server: " + err.Error())
		return
	}
	defer conn.Close()

	// First bow
	conn.Write([]byte{0x05, 0x01, 0x00})

	rsp := make([]byte, 512)
	rlen, err := conn.Read(rsp)
	if err != nil {
		log_err("handshake response: " + err.Error())
		return
	}
	log_raw("handshake", rsp[:rlen])

	// Send SOCKS header, connect to this IP on this port
	bbuff := new(bytes.Buffer)
	bbuff.Write([]byte{0x05, 0x01, 0x00, 0x01})
	bbuff.Write(net.ParseIP(request.DNS).To4())
	bbuff.Write([]byte{0x00, 53})

	log_raw("header", bbuff.Bytes()[:10])
	_, err = conn.Write(bbuff.Bytes()[:10])
	if err != nil {
		log_err("send header: " + err.Error())
		return
	}

	rsp = make([]byte, 512)
	rlen, err = conn.Read(rsp)
	if err != nil {
		log_err("header response: " + err.Error())
		return
	}
	log_raw("rsp", rsp[:rlen])

	// Need to prepend query length since we get this from UDP
	// (TCP doesn't need this)
	sbuff := new(bytes.Buffer)
	if err = binary.Write(sbuff, binary.BigEndian, int16(len(request.Data))); err != nil {
		log_err("packet length: " + err.Error())
		return
	}
	sbuff.Write(request.Data)

	log_raw("query", sbuff.Bytes())
	_, err = conn.Write(sbuff.Bytes())
	if err != nil {
		log_err("send query: " + err.Error())
		return
	}

	rsp = make([]byte, 2048)
	rlen, err = conn.Read(rsp)
	if err != nil {
		log_err("query response: " + err.Error())
		return
	}

	// Send back to UDP, do not want the length
	log_raw("rsp", rsp[2:rlen])
	_, err = request.Cconn.WriteToUDP(rsp[2:rlen], request.SourceAddr)
	if err != nil {
		log_err("forward response: " + err.Error())
	}

	if cache {
		setCache(request.Data, rsp[2:rlen])
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

	if cache && exists && (time.Since(entry.CreatedAt) <= CacheTTL*time.Second) {
		answer := new(bytes.Buffer)
		answer.Write(q[:2])
		answer.Write(entry.Data)
		c.WriteToUDP(answer.Bytes(), target)
		return true
	}

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
		log_info("not a root, will keep running as " + current.Username)
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

func log_err(msg string) {
	fmt.Printf("[!] %s\n", msg)
}
func log_info(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func log_raw(label string, msg interface{}) {
	if debug {
		fmt.Printf("[*] <%s> %q\n", label, msg)
	}
}
