package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
)

type lookupRequest struct {
	Cconn      *net.UDPConn
	Data       []byte
	DNS        string
	SourceAddr *net.UDPAddr
}

var (
	bindAddr   string
	socksAddr  string
	resolvFile string
	debug      bool
)

func init() {
	flag.StringVar(&bindAddr, "b", "127.0.0.1:53", "Bind to address, default to localhost:53")
	flag.StringVar(&socksAddr, "s", "127.0.0.1:8080", "Use this SOCKS connection, default to localhost:8080")
	flag.StringVar(&resolvFile, "r", "./resolv.conf", "Use dns listed in this file, default to ./resolv.conf")
	flag.BoolVar(&debug, "d", false, "Set debug mode")
}

func main() {
	flag.Parse()

	rand.Seed(666)

	// open resolver file, create dns list
	DNSlist, err := readResolvConf(resolvFile)
	if err != nil {
		log_err("can't read resolv.conf: " + err.Error())
		os.Exit(1)
	}

	// bind to dns port and wait
	bindDNS(bindAddr, socksAddr, DNSlist)
}

func log_err(msg string) {
	fmt.Printf("[!] %s\n", msg)
}
func log_info(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func log_raw(label string, msg interface{}) {
	if debug {
		fmt.Printf("%s> %q\n", label, msg)
	}
}

func readResolvConf(rfile string) ([]string, error) {
	content, err := ioutil.ReadFile(rfile)
	content = bytes.TrimSpace(content)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}

func connectSOCKS(addr string, request *lookupRequest) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// First bow
	conn.Write([]byte{0x5, 0x01, 0x00})

	rsp := make([]byte, 512)
	rlen, err := conn.Read(rsp)
	if err != nil {
		return err
	}
	log_raw("handshake", rsp[:rlen])

	bbuff := new(bytes.Buffer)
	bbuff.Write([]byte{0x05, 0x01, 0x00, 0x01})
	bbuff.Write(net.ParseIP(request.DNS).To4())
	bbuff.Write([]byte{0x00, 0x35})

	log_raw("header", bbuff.Bytes()[:10])
	_, err = conn.Write(bbuff.Bytes()[:10])
	if err != nil {
		return err
	}

	rsp = make([]byte, 512)
	rlen, err = conn.Read(rsp)
	if err != nil {
		return err
	}
	log_raw("rsp", rsp[:rlen])

	sbuff := new(bytes.Buffer)
	if err = binary.Write(sbuff, binary.BigEndian, int16(len(request.Data))); err != nil {
		return err
	}

	sbuff.Write(request.Data)
	log_raw("query", sbuff.Bytes())
	_, err = conn.Write(sbuff.Bytes())
	if err != nil {
		log_err("can't write")
		return err
	}

	rsp = make([]byte, 2048)
	rlen, err = conn.Read(rsp)
	if err != nil {
		log_err("can't read")
		return err
	}
	log_raw("rsp", rsp[2:rlen-2])

	_, err = request.Cconn.WriteToUDP(rsp[2:rlen-2], request.SourceAddr)

	return err
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

	log_info("start accepting connection...")

	for {
		rdata := make([]byte, 2048)
		rlen, rAddr, err := L.ReadFromUDP(rdata)
		if err != nil {
			log_err("can not read request: " + err.Error())
			return
		}
		log_raw("rdata", rdata[:rlen])

		go func(c *net.UDPConn, data []byte, target *net.UDPAddr) {

			if err = connectSOCKS(socksaddr, &lookupRequest{
				Cconn:      c,
				Data:       data,
				DNS:        list[rand.Intn(len(list))],
				SourceAddr: target,
			}); err != nil {
				log_err(err.Error())
			}
		}(L, rdata[:rlen], rAddr)
	}
}
