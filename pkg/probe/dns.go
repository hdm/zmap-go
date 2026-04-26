package probe

import (
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
)

// DNS is a UDP-based DNS query probe with full reply parsing. The default
// query is A IN <name>. Mirrors src/probe_modules/module_dns.c.
type DNS struct {
	UDP
	Question string
	QType    uint16
}

// NewDNS returns a DNS probe.
func NewDNS(name string, qtype uint16, srcFirst, srcLast uint16, ttl uint8, ipOnly bool) (*DNS, error) {
	body, err := packet.DNSQueryPayload(name, qtype, 0x1234)
	if err != nil {
		return nil, err
	}
	d := &DNS{
		UDP: UDP{
			Payload:      body,
			SrcPortFirst: srcFirst, SrcPortLast: srcLast,
			TTL: ttl, SendIPOnly: ipOnly,
		},
		Question: name, QType: qtype,
	}
	d.UDP.PostValidate = d.parseReply
	return d, nil
}
func (m *DNS) Name() string { return "dns" }

func (m *DNS) Fields() []FieldDef {
	return []FieldDef{
		{"dns_id", FieldInt, "DNS transaction ID"},
		{"dns_rcode", FieldInt, "DNS RCODE"},
		{"dns_qr", FieldBool, "DNS QR (response) bit"},
		{"dns_aa", FieldBool, "Authoritative Answer flag"},
		{"dns_tc", FieldBool, "Truncation flag"},
		{"dns_rd", FieldBool, "Recursion Desired flag"},
		{"dns_ra", FieldBool, "Recursion Available flag"},
		{"dns_qdcount", FieldInt, "Question count"},
		{"dns_ancount", FieldInt, "Answer count"},
		{"dns_nscount", FieldInt, "Authority count"},
		{"dns_arcount", FieldInt, "Additional count"},
		{"dns_questions", FieldString, "decoded questions, comma-separated"},
		{"dns_answers", FieldString, "decoded answers, comma-separated"},
		{"dns_parse_err", FieldString, "non-empty when parse failed"},
	}
}

func (m *DNS) parseReply(r *Result, udp *layers.UDP) bool {
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		r.Extra["dns_parse_err"] = err.Error()
		// Keep classification "udp" — payload arrived but we couldn't decode.
		r.Classification = "dns_parse_err"
		return true
	}
	r.Extra["dns_id"] = uint64(dns.ID)
	r.Extra["dns_rcode"] = uint64(dns.ResponseCode)
	r.Extra["dns_qr"] = dns.QR
	r.Extra["dns_aa"] = dns.AA
	r.Extra["dns_tc"] = dns.TC
	r.Extra["dns_rd"] = dns.RD
	r.Extra["dns_ra"] = dns.RA
	r.Extra["dns_qdcount"] = uint64(len(dns.Questions))
	r.Extra["dns_ancount"] = uint64(len(dns.Answers))
	r.Extra["dns_nscount"] = uint64(len(dns.Authorities))
	r.Extra["dns_arcount"] = uint64(len(dns.Additionals))

	qs := make([]string, 0, len(dns.Questions))
	for _, q := range dns.Questions {
		qs = append(qs, string(q.Name)+" "+q.Type.String()+" "+q.Class.String())
	}
	r.Extra["dns_questions"] = strings.Join(qs, ",")

	ans := make([]string, 0, len(dns.Answers))
	for _, a := range dns.Answers {
		val := ""
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if a.IP != nil {
				val = a.IP.String()
			}
		case layers.DNSTypeCNAME:
			val = string(a.CNAME)
		case layers.DNSTypeNS:
			val = string(a.NS)
		case layers.DNSTypePTR:
			val = string(a.PTR)
		case layers.DNSTypeMX:
			val = string(a.MX.Name)
		case layers.DNSTypeTXT:
			val = strings.Join(byteSlicesToStrings(a.TXTs), ";")
		case layers.DNSTypeSOA:
			val = string(a.SOA.MName) + " " + string(a.SOA.RName)
		default:
			val = string(a.Data)
		}
		ans = append(ans, string(a.Name)+" "+a.Type.String()+" "+val)
	}
	r.Extra["dns_answers"] = strings.Join(ans, ",")
	r.Classification = "dns"
	r.Success = dns.QR && dns.ResponseCode == layers.DNSResponseCodeNoErr
	return true
}

func byteSlicesToStrings(in [][]byte) []string {
	out := make([]string, len(in))
	for i, b := range in {
		out[i] = string(b)
	}
	return out
}
