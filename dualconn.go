package dualconn

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/smallnest/gopacket/layers"
	qbpf "github.com/smallnest/qianmo/bpf"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// IPv4Flag represents the flags in an IPv4 header.
type IPv4Flag uint8

// DualConn represents a connection that combines an IPv4 raw connection and a UDP connection.
// It is used to send UDP packets with raw IP headers.
// And receive UDP packets with net.recvConn.
type DualConn struct {
	sendConn *ipv4.RawConn // IPv4 raw connection for sending UDP packets
	recvConn *net.UDPConn  // UDP connection for receiving UDP packets

	localIP string

	timeout time.Duration

	tos      uint8
	ttl      uint8
	ipv4Flag IPv4Flag
}

// NewDualConn creates a new DualConn.
// It creates an IPv4 raw connection for sending UDP packets with raw IP headers.
// And a UDP connection for receiving UDP packets.
//
// @param localAddr: the local IP address to bind for sending UDP packets
// @param port: the local port to bind for receiving UDP packets
func NewDualConn(localAddr string, port int) (*DualConn, error) {
	pconn, err := net.ListenPacket("ip:udp", localAddr)
	if err != nil {
		return nil, err
	}

	// Create an IPv4 raw connection
	sendConn, err := ipv4.NewRawConn(pconn)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	// only send packets, not for receiving, so configure the drop all filter
	dropAllFilter := createDropAllBPF()
	filter, err := bpf.Assemble(dropAllFilter)
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}
	err = sendConn.SetBPF(filter)
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}

	uconn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(localAddr),
		Port: port,
	})
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}

	return &DualConn{
		sendConn: sendConn,
		recvConn: uconn,

		ttl: 64,
	}, nil
}

func createDropAllBPF() []bpf.Instruction {
	return []bpf.Instruction{
		bpf.RetConstant{Val: 0},
	}
}

// SetTimeout sets the timeout for the connection.
func (c *DualConn) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetTOS sets the Type of Service (TOS) for the connection.
func (c *DualConn) SetTOS(tos uint8) {
	c.tos = tos
}

// SetTTL sets the Time To Live (TTL) for the connection.
func (c *DualConn) SetTTL(ttl uint8) {
	c.ttl = ttl
}

// SetIPv4Flag sets the IPv4 flag for the connection.
func (c *DualConn) SetIPv4Flag(flag IPv4Flag) {
	c.ipv4Flag = flag
}

// WriteToIP writes UDP data to the specified destination IP and port.
func (c *DualConn) WriteToIP(payload []byte, localIP, remoteIP string, localPort, remotePort uint16) (int, error) {
	if localIP == "" {
		localIP = c.localIP
	}

	data, err := EncodeIPPacket(localIP, remoteIP, localPort, remotePort, payload, c.ttl, c.tos, layers.IPv4Flag(c.ipv4Flag))
	if err != nil {
		return 0, fmt.Errorf("failed to encode IP packet: %w", err)
	}

	if c.timeout > 0 {
		c.sendConn.SetDeadline(time.Now().Add(c.timeout))
	}
	n, err := c.sendConn.WriteToIP(data, &net.IPAddr{IP: net.ParseIP(remoteIP)})
	if err != nil {
		return 0, fmt.Errorf("failed to write to IP: %w", err)
	}
	return n, nil
}

// ReadFrom reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *DualConn) Read(b []byte) (int, error) {
	return c.recvConn.Read(b)
}

// ReadFrom reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *DualConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.recvConn.ReadFrom(b)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *DualConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	return c.recvConn.ReadFromUDPAddrPort(b)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the oob data, the flags, the source address and the error.
func (c *DualConn) ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	return c.recvConn.ReadMsgUDPAddrPort(b, oob)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *DualConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	return c.recvConn.ReadFromUDP(b)
}

// SetBBF sets the BPF filter for the connection.
func (c *DualConn) SetBBF(filter []bpf.RawInstruction) error {
	return c.sendConn.SetBPF(filter)
}

// SetBBFExpr sets the BPF filter for the connection.
// It parses the filter expression like tcpdump and sets the BPF filter.
func (c *DualConn) SetBBFExpr(expr string) error {
	filter := qbpf.ParseTcpdumpFitlerData(expr)
	return c.sendConn.SetBPF(filter)
}

// Close closes the connection.
func (c *DualConn) Close() error {
	_ = c.sendConn.Close()
	return c.recvConn.Close()
}
