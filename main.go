package main

import (
	"bytes"
	"flag"
	"fmt"
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
)

func init() {
	flag.StringVar(&bindAddr, "b", "127.0.0.1:53", "Bind to address, default to localhost:53")
	flag.StringVar(&socksAddr, "s", "127.0.0.1:8080", "Use this SOCKS connection, default to localhost:8080")
	flag.StringVar(&resolvFile, "r", "./resolv.conf", "Use dns listed in this file, default to ./resolv.conf")
}

func main() {
	flag.Parse()

	// open resolver file, create dns list
	DNSlist, err := readResolvConf(resolvFile)
	if err != nil {
		log_err("can't read resolv.conf: " + err.Error())
		os.Exit(1)
	}

	// open connection to socks server
	// wait on a channel for incoming lookup request
	socksChan, err := connectSOCKS(socksAddr)
	if err != nil {
		log_err("can't connect to SOCKS5 server: " + err.Error())
		os.Exit(2)
	}
	defer close(socksChan)

	// bind to dns port and wait
	bindDNS(bindAddr, socksChan, DNSlist)
}

func log_err(msg string) {
	fmt.Printf("[!] %s\n", msg)
}
func log_info(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func log_raw(label string, msg interface{}) {
	fmt.Printf("%s> %q\n", label, msg)
}

func readResolvConf(rfile string) ([]string, error) {
	content, err := ioutil.ReadFile(rfile)
	content = bytes.TrimSpace(content)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}

func connectSOCKS(addr string) (chan *lookupRequest, error) {
	_rsp := []byte{}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// First bow
	conn.Write([]byte{0x5, 0x01, 0x00})

	_, err = conn.Read(_rsp)
	log_raw("hs", _rsp)

	reqChan := make(chan *lookupRequest, 512)
	go func() {
		for {
			request, ok := <-reqChan
			if !ok {
				log_info("stop proxying...")
				return
			}

			bbuff := new(bytes.Buffer)

			bbuff.Write([]byte{0x05, 0x01, 0x00, 0x01})
			bbuff.Write(net.ParseIP(request.DNS).To4())
			bbuff.Write([]byte{0x00, 0x35})

			log_raw("bbuff", bbuff.Bytes()[:10])
			_, err := conn.Write(bbuff.Bytes()[:10])
			if err != nil {
				log_err("fail to send header: " + err.Error())
				continue
			}

			rsp := make([]byte, 512)
			rlen, err := conn.Read(rsp)
			if err != nil {
				log_err("fail reading header response: " + err.Error())
				continue
			}

			log_raw("header", rsp[:rlen])

			_, err = conn.Write(request.Data)
			if err != nil {
				log_err("fail to send data: " + err.Error())
				continue
			}

			rsp = make([]byte, 2048)
			rlen, err = conn.Read(rsp)
			if err != nil {
				log_err("fail reading lookup response: " + err.Error())
				continue
			}

			log_raw("lookup", rsp[:rlen])
			_, err = request.Cconn.Write(rsp[:rlen])
			if err != nil {
				log_err("fail to send-back lookup response: " + err.Error())
			}
			request.Cconn.Close()
		}
	}()

	return reqChan, nil
}

func bindDNS(addr string, sockschan chan *lookupRequest, list []string) (chan error, error) {
	L, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
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
			log_info("read data...")
			rdata := make([]byte, 2048)
			rlen, err := conn.Read(rdata)
			if err != nil {
				log_err("can not read request: " + err.Error())
				return
			}
			log_raw("rdata", rdata[:rlen])
			sockschan <- &lookupRequest{
				Cconn: conn,
				Data:  rdata[:rlen],
				DNS:   "8.8.8.8",
			}
		}(conn)
	}
}
