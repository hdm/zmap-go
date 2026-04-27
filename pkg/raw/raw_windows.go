//go:build windows

package raw

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// winConn implements PacketConn on Windows via Npcap's wpcap.dll, which is
// loaded dynamically by gopacket/pcap's syscall.LazyDLL bindings (no CGO).
//
// Runtime requirement: Npcap (https://npcap.com) installed in the default
// "Install Npcap in WinPcap API-compatible Mode" configuration.
type winConn struct {
	intf *net.Interface
	h    *pcap.Handle
	mu   sync.Mutex // libpcap WritePacketData is not goroutine-safe
}

func listenPacket(intf *net.Interface) (PacketConn, error) {
	dev, err := pcapDeviceForInterface(intf)
	if err != nil {
		return nil, err
	}
	// 65536-byte snaplen, no promisc, 1ms read timeout (timeout 0 blocks
	// forever on Windows, which would deadlock shutdown).
	h, err := pcap.OpenLive(dev, 65536, false, time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("raw: pcap.OpenLive %s: %w", dev, err)
	}
	return &winConn{intf: intf, h: h}, nil
}

func pcapDeviceForInterface(intf *net.Interface) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("raw: pcap.FindAllDevs: %w (is Npcap installed?)", err)
	}
	addrs, err := intf.Addrs()
	if err != nil {
		return "", err
	}
	want := make([][]byte, 0, len(addrs))
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && ip.To4() != nil {
			want = append(want, ip.To4())
		}
	}
	for _, d := range devs {
		if strings.EqualFold(d.Description, intf.Name) {
			return d.Name, nil
		}
		for _, a := range d.Addresses {
			if v4 := a.IP.To4(); v4 != nil {
				for _, w := range want {
					if bytes.Equal(v4, w) {
						return d.Name, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("raw: no Npcap device matches interface %s", intf.Name)
}

func (c *winConn) WriteTo(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.h.WritePacketData(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *winConn) ReadFrom(b []byte) (int, error) {
	for {
		data, _, err := c.h.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			return 0, err
		}
		return copy(b, data), nil
	}
}

func (c *winConn) Close() error              { c.h.Close(); return nil }
func (c *winConn) Interface() *net.Interface { return c.intf }
func (c *winConn) LinkType() string {
	switch c.h.LinkType().String() {
	case "Ethernet":
		return "ethernet"
	case "Loopback":
		return "loopback"
	case "Raw":
		return "raw"
	}
	return strings.ToLower(c.h.LinkType().String())
}

// NewSender on Windows delegates to WriteTo: libpcap's WritePacketData is
// not goroutine-safe, so all senders share the conn's mutex anyway.
type winSender struct{ c *winConn }

func (c *winConn) NewSender() (Sender, error) { return &winSender{c: c}, nil }
func (s *winSender) WriteTo(b []byte) (int, error) {
	return s.c.WriteTo(b)
}
func (s *winSender) WriteBatch(pkts [][]byte) (int, error) {
	for i, p := range pkts {
		if _, err := s.c.WriteTo(p); err != nil {
			return i, err
		}
	}
	return len(pkts), nil
}
func (s *winSender) Close() error { return nil }
