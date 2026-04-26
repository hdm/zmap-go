package probe

import (
	"net"

	"github.com/hdm/zmap-go/pkg/packet"
)

// NTP is a UDP-based NTP version 3/4 client probe (mode=3).
type NTP struct{ UDP }

// NewNTP returns an NTP probe with the canonical client request payload.
func NewNTP(srcPortFirst, srcPortLast uint16, ttl uint8, ipOnly bool) *NTP {
	return &NTP{UDP: UDP{
		Payload:      packet.NTPRequestPayload(),
		SrcPortFirst: srcPortFirst, SrcPortLast: srcPortLast,
		TTL: ttl, SendIPOnly: ipOnly,
	}}
}
func (m *NTP) Name() string { return "ntp" }

// DNS is a UDP-based DNS A-query probe.
type DNS struct {
	UDP
	Question string
	QType    uint16
}

// NewDNS returns a DNS probe with payload "<name> A IN".
func NewDNS(name string, qtype uint16, srcFirst, srcLast uint16, ttl uint8, ipOnly bool) (*DNS, error) {
	body, err := packet.DNSQueryPayload(name, qtype, 0x1234)
	if err != nil {
		return nil, err
	}
	return &DNS{
		UDP: UDP{
			Payload:      body,
			SrcPortFirst: srcFirst, SrcPortLast: srcLast,
			TTL: ttl, SendIPOnly: ipOnly,
		},
		Question: name, QType: qtype,
	}, nil
}
func (m *DNS) Name() string { return "dns" }

// IcmpEchoTime is ICMP echo carrying an 8-byte zmap timestamp payload.
type IcmpEchoTime struct {
	IcmpEcho
}

// NewIcmpEchoTime returns the timestamped ICMP echo probe.
func NewIcmpEchoTime(ttl uint8, ipOnly bool) *IcmpEchoTime {
	// 16-byte payload: 8 bytes timestamp space + 8 bytes pad. The validator
	// only checks Id and Seq, so the payload contents are advisory.
	return &IcmpEchoTime{IcmpEcho: IcmpEcho{
		Payload: make([]byte, 16),
		TTL:     ttl, SendIPOnly: ipOnly,
	}}
}
func (m *IcmpEchoTime) Name() string { return "icmp_echo_time" }

// ensure compile-time interface satisfaction.
var (
	_ Module = (*NTP)(nil)
	_ Module = (*DNS)(nil)
	_ Module = (*IcmpEchoTime)(nil)
	_        = net.IPv4
)
