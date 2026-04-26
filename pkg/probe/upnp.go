package probe

import (
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// UPnP sends an SSDP M-SEARCH (UDP/1900) and parses the HTTP response
// headers from the responder. Mirrors src/probe_modules/module_upnp.c.
type UPnP struct{ UDP }

const upnpQuery = "M-SEARCH * HTTP/1.1\r\n" +
	"Host:239.255.255.250:1900\r\n" +
	"ST:upnp:rootdevice\r\n" +
	"Man:\"ssdp:discover\"\r\nMX:3\r\n\r\n"

// NewUPnP returns a UPnP probe.
func NewUPnP(srcFirst, srcLast uint16, ttl uint8, ipOnly bool) *UPnP {
	u := &UPnP{UDP: UDP{
		Payload:      []byte(upnpQuery),
		SrcPortFirst: srcFirst, SrcPortLast: srcLast,
		TTL: ttl, SendIPOnly: ipOnly,
	}}
	u.UDP.PostValidate = u.parseReply
	return u
}
func (m *UPnP) Name() string { return "upnp" }
func (m *UPnP) Fields() []FieldDef {
	return []FieldDef{
		{"server", FieldString, "Server header"},
		{"location", FieldString, "Location header"},
		{"usn", FieldString, "USN header"},
		{"st", FieldString, "ST header"},
		{"ext", FieldString, "EXT header"},
		{"cache_control", FieldString, "Cache-Control header"},
		{"x_user_agent", FieldString, "X-User-Agent header"},
		{"agent", FieldString, "Agent header"},
		{"date", FieldString, "Date header"},
		{"data", FieldBinary, "raw UDP payload"},
	}
}

func (m *UPnP) parseReply(r *Result, udp *layers.UDP) bool {
	body := string(udp.Payload)
	r.Extra["data"] = append([]byte(nil), udp.Payload...)
	lines := strings.Split(body, "\n")
	if len(lines) == 0 {
		r.Classification = "no-http-header"
		r.Success = false
		return true
	}
	first := strings.TrimRight(lines[0], "\r")
	if !strings.HasPrefix(first, "HTTP/1.1 200") && !strings.HasPrefix(first, "HTTP/1.0 200") {
		r.Classification = "no-http-header"
		r.Success = false
		return true
	}
	r.Classification = "upnp"
	r.Success = true
	for _, ln := range lines[1:] {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			continue
		}
		i := strings.IndexByte(ln, ':')
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(ln[:i]))
		val := strings.TrimSpace(ln[i+1:])
		switch key {
		case "server":
			r.Extra["server"] = val
		case "location":
			r.Extra["location"] = val
		case "usn":
			r.Extra["usn"] = val
		case "st":
			r.Extra["st"] = val
		case "ext":
			r.Extra["ext"] = val
		case "cache-control":
			r.Extra["cache_control"] = val
		case "x-user-agent":
			r.Extra["x_user_agent"] = val
		case "agent":
			r.Extra["agent"] = val
		case "date":
			r.Extra["date"] = val
		}
	}
	return true
}
