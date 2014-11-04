package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

type lookupRequest struct {
	Cconn net.Conn
	Data  []byte
	DNS   string
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
	defer request.Cconn.Close()

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

	log_raw("query", request.Data)
	_, err = conn.Write(request.Data)
	if err != nil {
		return err
	}

	_, err = io.Copy(request.Cconn, conn)

	return err
}

func bindDNS(addr, socksaddr string, list []string) {
	L, err := net.Listen("tcp", addr)
	if err != nil {
		log_err(err.Error())
		return
	}
	defer L.Close()

	log_info("start accepting connection...")

	for {
		conn, err := L.Accept()
		if err != nil {
			log_err("can't accept connection: " + err.Error())
			continue
		}
		go func(c net.Conn) {
			rdata := make([]byte, 2048)
			rlen, err := conn.Read(rdata)
			if err != nil {
				log_err("can not read request: " + err.Error())
				return
			}
			log_raw("rdata", rdata[:rlen])

			if err = connectSOCKS(socksaddr, &lookupRequest{
				Cconn: conn,
				Data:  rdata[:rlen],
				DNS:   "8.8.8.8",
			}); err != nil {
				log_err(err.Error())
			}
		}(conn)
	}
}
