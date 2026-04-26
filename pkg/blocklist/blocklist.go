package blocklist

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/zmap/zmap/pkg/constraint"
)

const (
	Disallowed constraint.Value = 0
	Allowed    constraint.Value = 1
)

type CIDR struct {
	Address   netip.Addr
	PrefixLen int
}

type Config struct {
	AllowlistFile    string
	BlocklistFile    string
	AllowlistEntries []string
	BlocklistEntries []string
	IgnoreInvalid    bool
}

type List struct {
	constraint *constraint.Constraint
	allowed    []CIDR
	blocked    []CIDR
}

func New(config Config) (*List, error) {
	usingAllowlist := config.AllowlistFile != "" || len(config.AllowlistEntries) > 0
	defaultValue := Allowed
	if usingAllowlist {
		defaultValue = Disallowed
	}
	l := &List{constraint: constraint.New(defaultValue)}

	if config.AllowlistFile != "" {
		if err := l.addFile(config.AllowlistFile, Allowed, config.IgnoreInvalid); err != nil {
			return nil, err
		}
	}
	if err := l.addEntries(config.AllowlistEntries, Allowed, config.IgnoreInvalid); err != nil {
		return nil, err
	}
	if config.BlocklistFile != "" {
		if err := l.addFile(config.BlocklistFile, Disallowed, config.IgnoreInvalid); err != nil {
			return nil, err
		}
	}
	if err := l.addEntries(config.BlocklistEntries, Disallowed, config.IgnoreInvalid); err != nil {
		return nil, err
	}
	if err := l.AddPrefix(netip.MustParseAddr("0.0.0.0"), 32, Disallowed); err != nil {
		return nil, err
	}
	l.constraint.Paint(Allowed)
	if l.CountAllowed() == 0 {
		return nil, fmt.Errorf("no addresses are eligible to be scanned")
	}
	return l, nil
}

func (l *List) AddPrefix(addr netip.Addr, prefixLen int, value constraint.Value) error {
	if !addr.Is4() {
		return nil
	}
	if prefixLen < 0 || prefixLen > 32 {
		return fmt.Errorf("invalid IPv4 prefix length %d", prefixLen)
	}
	addr = addr.Unmap()
	if err := l.constraint.Set(ipv4ToUint32(addr), prefixLen, value); err != nil {
		return err
	}
	cidr := CIDR{Address: addr, PrefixLen: prefixLen}
	if value == Allowed {
		l.allowed = append(l.allowed, cidr)
	} else {
		l.blocked = append(l.blocked, cidr)
	}
	return nil
}

func (l *List) IsAllowed(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	return l.constraint.Lookup(ipv4ToUint32(addr.Unmap())) == Allowed
}

func (l *List) LookupIndex(index uint64) (netip.Addr, error) {
	value, err := l.constraint.LookupIndex(index, Allowed)
	if err != nil {
		return netip.Addr{}, err
	}
	return uint32ToIPv4(value), nil
}

func (l *List) CountAllowed() uint64 {
	return l.constraint.Count(Allowed)
}

func (l *List) CountNotAllowed() uint64 {
	return l.constraint.Count(Disallowed)
}

func (l *List) AllowedCIDRs() []CIDR {
	return append([]CIDR(nil), l.allowed...)
}

func (l *List) BlockedCIDRs() []CIDR {
	return append([]CIDR(nil), l.blocked...)
}

func (l *List) addEntries(entries []string, value constraint.Value, ignoreInvalid bool) error {
	for _, entry := range entries {
		if err := l.addString(entry, value); err != nil && !ignoreInvalid {
			return err
		}
	}
	return nil
}

func (l *List) addFile(path string, value constraint.Value, ignoreInvalid bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := l.addString(line, value); err != nil && !ignoreInvalid {
			return fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
	}
	return scanner.Err()
}

func (l *List) addString(input string, value constraint.Value) error {
	addrText, prefixLen, err := splitCIDR(input)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(addrText)
	if err == nil {
		return l.AddPrefix(addr, prefixLen, value)
	}
	addresses, err := net.LookupIP(addrText)
	if err != nil {
		return fmt.Errorf("parse IP address or hostname %q: %w", addrText, err)
	}
	added := false
	for _, ip := range addresses {
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipv4)
		if !ok || !addr.Is4() {
			continue
		}
		if err := l.AddPrefix(addr.Unmap(), prefixLen, value); err != nil {
			return err
		}
		added = true
	}
	if !added {
		return fmt.Errorf("hostname %q did not resolve to an IPv4 address", addrText)
	}
	return nil
}

func splitCIDR(input string) (string, int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, fmt.Errorf("empty CIDR")
	}
	addrText := input
	prefixLen := 32
	if slash := strings.LastIndexByte(input, '/'); slash >= 0 {
		addrText = input[:slash]
		if strings.Contains(addrText, ":") {
			return addrText, 0, nil
		}
		lengthText := input[slash+1:]
		length, err := strconv.Atoi(lengthText)
		if err != nil || length < 0 || length > 32 {
			return "", 0, fmt.Errorf("invalid IPv4 prefix length %q", lengthText)
		}
		prefixLen = length
	}
	if strings.Contains(addrText, ":") {
		return addrText, prefixLen, nil
	}
	return addrText, prefixLen, nil
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

func uint32ToIPv4(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}
