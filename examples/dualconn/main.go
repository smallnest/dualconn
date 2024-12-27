package main

import (
	"fmt"
	"net"
	"time"

	"github.com/smallnest/dualconn"
)

func main() {
	go startServer()

	conn, err := dualconn.NewDualConn("127.0.0.1", 40000)
	if err != nil {
		panic(err)
	}

	var buf = make([]byte, 1024)
	localPort := uint16(20000)
	for {
		payload := dualconn.MakePayload(dualconn.PayloadType5A, 1024)
		err = dualconn.EncodePayloadWithPort(uint64(time.Now().UnixNano()), 8888,
			localPort, 30000, payload, dualconn.PayloadType5A)
		if err != nil {
			panic(err)
		}
		data, err := dualconn.SimpleEncodeIPPacket("127.0.0.1", "127.0.0.1", localPort, 30000, payload)
		if err != nil {
			panic(err)
		}

		_, err = conn.WriteToIP(data, "127.0.0.1", "127.0.0.1", localPort, 30000)
		if err != nil {
			panic(err)
		}
		localPort++
		if localPort == 21000 {
			localPort = 20000
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}

		ts, seq, payloadType, err := dualconn.DecodePayload(buf[:n])
		if err != nil {
			panic(err)
		}
		isSame, _ := dualconn.ComparePayload(payload, buf[:n], 21, 1024-21)

		fmt.Printf("received from %s, ts: %v, seq: %v, pt: %v, same:%t\n", addr.String(), ts, seq, payloadType, isSame)
	}
}

func startServer() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 30000})
	if err != nil {
		panic(err)
	}

	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("server received from %s: %s\n", addr.String(), buf[:n])

		addr.Port = 40000
		_, _ = conn.WriteToUDP(buf[:n], addr)
	}
}
