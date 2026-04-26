// cmd/zmap is a CGO-free Go port of the zmap fast Internet scanner.
//
// Probe modules: tcp_synscan, tcp_synackscan, icmp_echo, icmp_echo_time, udp,
// dns, ntp, upnp, bacnet, ipip.
//
// Output modules: default (saddr per line), csv, json. An optional
// --output-filter expression suppresses results that do not match.
//
// Send paths: --dryrun (write targets to stdout) or raw L2 (AF_PACKET on
// Linux / BPF on BSD) with up to runtime.NumCPU()-1 sender goroutines.
// Gateway MAC is auto-detected via the OS routing table + ARP when not
// supplied with --gateway-mac.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/blocklist"
	"github.com/hdm/zmap-go/pkg/cyclic"
	"github.com/hdm/zmap-go/pkg/filter"
	"github.com/hdm/zmap-go/pkg/gateway"
	"github.com/hdm/zmap-go/pkg/iterator"
	"github.com/hdm/zmap-go/pkg/monitor"
	"github.com/hdm/zmap-go/pkg/output"
	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/ports"
	"github.com/hdm/zmap-go/pkg/probe"
	"github.com/hdm/zmap-go/pkg/raw"
	"github.com/hdm/zmap-go/pkg/shard"
	"github.com/hdm/zmap-go/pkg/validate"
)

const version = "DEVELOPMENT"

type options struct {
	module         string
	probeArgs      string
	targetPorts    string
	blocklistFile  string
	allowlistFile  string
	outputFile     string
	outputModule   string
	outputFields   string
	logFile        string
	iface          string
	srcIP          string
	srcMAC         string
	gwMAC          string
	srcPortRange   string
	rate           int
	maxTargets     string
	maxResults     int
	maxRuntime     int
	cooldown       int
	verbosity      int
	senderThreads  int
	dryrun         bool
	sendIPOnly     bool
	seed           uint64
	seedGiven      bool
	shards         int
	shard          int
	shardGiven     bool
	shardsGiven    bool
	versionFlag    bool
	destinations   []string
	style          string
	outputFilter   string
	quiet          bool
	noSummary      bool
	statusInterval int
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "zmap: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	conf, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	if conf.versionFlag {
		fmt.Fprintf(stdout, "zmap %s\n", version)
		return nil
	}
	if (conf.shardGiven || conf.shardsGiven) && !conf.seedGiven {
		return errors.New("need to specify seed if sharding a scan")
	}
	if conf.shardGiven != conf.shardsGiven {
		return errors.New("need to specify both --shard and --shards")
	}
	if conf.shards < 1 || conf.shards > 65535 {
		return errors.New("shards must be between 1 and 65535")
	}
	if conf.shard < 0 || conf.shard >= conf.shards {
		return errors.New("shard out of range")
	}

	out := stdout
	if conf.outputFile != "" && conf.outputFile != "-" {
		f, err := os.Create(conf.outputFile)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer f.Close()
		out = f
	}
	fields := output.DefaultFields()
	if conf.outputFields != "" {
		fields = splitTrim(conf.outputFields)
	}
	outMod := conf.outputModule
	if outMod == "" {
		outMod = "default"
	}
	var filt output.Filter
	if conf.outputFilter != "" {
		expr, ferr := filter.Parse(conf.outputFilter)
		if ferr != nil {
			return fmt.Errorf("--output-filter: %w", ferr)
		}
		filt = expr
	}
	w, err := output.NewWithConfig(out, output.Config{Module: outMod, Fields: fields, Filter: filt})
	if err != nil {
		return err
	}
	defer w.Close()

	spFirst, spLast, err := parseSrcPorts(conf.srcPortRange)
	if err != nil {
		return err
	}

	module, portList, err := buildModule(conf, spFirst, spLast)
	if err != nil {
		return err
	}

	bl, err := blocklist.New(blocklist.Config{
		AllowlistFile:    conf.allowlistFile,
		BlocklistFile:    conf.blocklistFile,
		AllowlistEntries: conf.destinations,
	})
	if err != nil {
		return fmt.Errorf("blocklist: %w", err)
	}
	if bl.CountAllowed() == 0 {
		return errors.New("no allowed addresses")
	}

	src := cyclic.Uint64Source(cyclic.SecureSource{})
	if conf.seedGiven {
		src = cyclic.NewSeedSource(conf.seed)
	}
	maxTargets, err := parseMaxTargets(conf.maxTargets, len(portList))
	if err != nil {
		return err
	}
	numThreads := conf.senderThreads
	if numThreads <= 0 {
		numThreads = runtime.NumCPU() - 1
		if numThreads < 1 {
			numThreads = 1
		}
	}
	if conf.dryrun {
		numThreads = 1
	}
	if numThreads > 255 {
		numThreads = 255
	}
	it, err := iterator.New(iterator.Config{
		NumThreads:      uint8(numThreads),
		ShardIndex:      uint16(conf.shard),
		NumShards:       uint16(conf.shards),
		NumAddrs:        bl.CountAllowed(),
		Ports:           portList,
		MaxTotalTargets: maxTargets,
		Source:          src,
		LookupIndex:     bl.LookupIndex,
	})
	if err != nil {
		return err
	}

	var v *validate.Validator
	if conf.seedGiven {
		v, err = validate.NewFromSeed(conf.seed)
	} else {
		v, err = validate.New()
	}
	if err != nil {
		return err
	}

	if conf.dryrun {
		s, err := it.Shard(0)
		if err != nil {
			return err
		}
		return runDryrun(s, w, conf, maxTargets)
	}

	intf, err := pickInterface(conf.iface)
	if err != nil {
		return err
	}
	srcIP, err := pickSrcIP(intf, conf.srcIP)
	if err != nil {
		return err
	}
	srcMAC, err := pickSrcMAC(intf, conf.srcMAC, conf.sendIPOnly)
	if err != nil {
		return err
	}
	conn, err := raw.ListenPacket(intf.Name)
	if err != nil {
		return fmt.Errorf("open raw socket on %s: %w (raw L2 sockets need privileges)", intf.Name, err)
	}
	defer conn.Close()

	var dstMAC net.HardwareAddr
	if !conf.sendIPOnly {
		dstMAC, err = resolveGatewayMAC(intf, srcIP, srcMAC, conf.gwMAC, conn, stderr)
		if err != nil {
			return err
		}
	}

	ctx, cancel := signalContext()
	defer cancel()
	if conf.maxRuntime > 0 {
		var runCancel context.CancelFunc
		ctx, runCancel = context.WithTimeout(ctx, time.Duration(conf.maxRuntime)*time.Second)
		defer runCancel()
	}

	results := make(chan probe.Result, 4096)
	counters := &monitor.Counters{}

	var monitorCancel context.CancelFunc
	monStart := time.Now()
	if !conf.quiet {
		interval := time.Duration(conf.statusInterval) * time.Second
		if interval <= 0 {
			interval = time.Second
		}
		var mctx context.Context
		mctx, monitorCancel = context.WithCancel(ctx)
		go monitor.Run(mctx, stderr, counters, interval, maxTargets)
	}

	var senderWG sync.WaitGroup
	perThreadRate := 0
	if conf.rate > 0 {
		perThreadRate = conf.rate / numThreads
		if perThreadRate < 1 {
			perThreadRate = 1
		}
	}
	for i := 0; i < numThreads; i++ {
		threadShard, err := it.Shard(uint8(i))
		if err != nil {
			return err
		}
		senderWG.Add(1)
		go func(s *shard.Shard) {
			defer senderWG.Done()
			runSender(ctx, conn, s, module, v, srcIP, srcMAC, dstMAC, perThreadRate, counters)
		}(threadShard)
	}

	var recvWG sync.WaitGroup
	recvCtx, stopRecv := context.WithCancel(ctx)
	recvWG.Add(1)
	go func() {
		defer recvWG.Done()
		runReceiver(recvCtx, conn, module, v, srcIP, spFirst, spLast, results, counters)
	}()

	go func() {
		senderWG.Wait()
		t := time.NewTimer(time.Duration(conf.cooldown) * time.Second)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		stopRecv()
	}()

	written := 0
	done := func() {
		if monitorCancel != nil {
			monitorCancel()
		}
		if !conf.noSummary {
			monitor.PrintSummary(stderr, counters, time.Since(monStart))
		}
	}
	for {
		select {
		case <-recvCtx.Done():
			recvWG.Wait()
			drainResults(results, w, &written, conf.maxResults, counters)
			done()
			return nil
		case r := <-results:
			if r.Success {
				counters.Success.Add(1)
			} else {
				counters.Failure.Add(1)
			}
			if err := w.WriteResult(r); err == nil {
				written++
			}
			if conf.maxResults > 0 && written >= conf.maxResults {
				cancel()
			}
		}
	}
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func drainResults(ch <-chan probe.Result, w output.Writer, written *int, max int, c *monitor.Counters) {
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return
			}
			if r.Success {
				c.Success.Add(1)
			} else {
				c.Failure.Add(1)
			}
			_ = w.WriteResult(r)
			*written++
			if max > 0 && *written >= max {
				return
			}
		default:
			return
		}
	}
}

func runDryrun(s *shard.Shard, w output.Writer, conf options, maxTargets uint64) error {
	cur, err := s.CurrentTarget()
	if err != nil {
		return err
	}
	srcIP := net.ParseIP(conf.srcIP)
	var count uint64
	for cur.Status == shard.OK {
		if maxTargets > 0 && count >= maxTargets {
			break
		}
		dstAddr := cur.IP.As4()
		_ = w.WriteResult(probe.Result{
			SrcIP:          srcIP,
			DstIP:          net.IPv4(dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]),
			DstPort:        cur.Port,
			Classification: "dryrun",
		})
		count++
		cur, err = s.NextTarget()
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

func runSender(ctx context.Context, conn raw.PacketConn, s *shard.Shard, m probe.Module,
	v *validate.Validator, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, rate int, c *monitor.Counters) {
	cur, err := s.CurrentTarget()
	if err != nil {
		return
	}
	var ticker *time.Ticker
	if rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(rate))
		defer ticker.Stop()
	}
	srcU := ipToBE(srcIP)
	for cur.Status == shard.OK {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if ticker != nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
		dst := cur.IP.As4()
		dstIP := net.IPv4(dst[0], dst[1], dst[2], dst[3])
		dstU := ipToBE(dstIP)
		t := v.GenWords(srcU, dstU, uint32(cur.Port), 0)
		pkt, _, err := m.BuildProbe(srcIP, dstIP, cur.Port, srcMAC, dstMAC, uint16(t[2]), t)
		if err == nil {
			if _, werr := conn.WriteTo(pkt); werr == nil {
				c.Sent.Add(1)
			} else {
				c.SendFail.Add(1)
			}
		} else {
			c.SendFail.Add(1)
		}
		cur, err = s.NextTarget()
		if err != nil {
			return
		}
	}
}

func runReceiver(ctx context.Context, conn raw.PacketConn, m probe.Module,
	v *validate.Validator, srcIP net.IP, spFirst, spLast uint16,
	out chan<- probe.Result, c *monitor.Counters) {
	buf := make([]byte, 65536)
	dec := layers.LayerTypeEthernet
	if conn.LinkType() == "raw" || conn.LinkType() == "loop" {
		dec = layers.LayerTypeIPv4
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		if n <= 0 {
			continue
		}
		c.Recv.Add(1)
		pkt := gopacket.NewPacket(buf[:n], dec, gopacket.NoCopy)
		if r, ok := m.ValidatePacket(pkt, v, srcIP, spFirst, spLast); ok {
			select {
			case out <- *r:
			case <-ctx.Done():
				return
			}
		}
	}
}

func ipToBE(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func buildModule(conf options, spFirst, spLast uint16) (probe.Module, []uint16, error) {
	switch conf.module {
	case "", "tcp_synscan":
		if conf.targetPorts == "" {
			return nil, nil, errors.New("tcp_synscan requires --target-ports")
		}
		p, err := ports.Parse(conf.targetPorts)
		if err != nil {
			return nil, nil, err
		}
		style, err := packet.ParseStyle(conf.style)
		if err != nil {
			return nil, nil, err
		}
		return &probe.TCPSyn{Style: style, TTL: 255, SendIPOnly: conf.sendIPOnly,
			SrcPortFirst: spFirst, SrcPortLast: spLast}, p.Ports, nil
	case "tcp_synackscan":
		if conf.targetPorts == "" {
			return nil, nil, errors.New("tcp_synackscan requires --target-ports")
		}
		p, err := ports.Parse(conf.targetPorts)
		if err != nil {
			return nil, nil, err
		}
		return &probe.TCPSynAck{TTL: 255, SendIPOnly: conf.sendIPOnly,
			SrcPortFirst: spFirst, SrcPortLast: spLast}, p.Ports, nil
	case "icmp_echo", "icmp":
		payload := []byte("ZMAPGOPING12345678AB")
		if strings.HasPrefix(conf.probeArgs, "text:") {
			payload = []byte(strings.TrimPrefix(conf.probeArgs, "text:"))
		}
		return &probe.IcmpEcho{Payload: payload, TTL: 255, SendIPOnly: conf.sendIPOnly}, []uint16{0}, nil
	case "icmp_echo_time":
		return probe.NewIcmpEchoTime(255, conf.sendIPOnly), []uint16{0}, nil
	case "udp":
		if conf.targetPorts == "" {
			return nil, nil, errors.New("udp requires --target-ports")
		}
		p, err := ports.Parse(conf.targetPorts)
		if err != nil {
			return nil, nil, err
		}
		var payload []byte
		if strings.HasPrefix(conf.probeArgs, "text:") {
			payload = []byte(strings.TrimPrefix(conf.probeArgs, "text:"))
		}
		return &probe.UDP{Payload: payload, TTL: 255, SendIPOnly: conf.sendIPOnly,
			SrcPortFirst: spFirst, SrcPortLast: spLast}, p.Ports, nil
	case "ntp":
		portsStr := conf.targetPorts
		if portsStr == "" {
			portsStr = "123"
		}
		p, err := ports.Parse(portsStr)
		if err != nil {
			return nil, nil, err
		}
		return probe.NewNTP(spFirst, spLast, 255, conf.sendIPOnly), p.Ports, nil
	case "dns":
		portsStr := conf.targetPorts
		if portsStr == "" {
			portsStr = "53"
		}
		p, err := ports.Parse(portsStr)
		if err != nil {
			return nil, nil, err
		}
		name := conf.probeArgs
		if name == "" {
			name = "www.example.com"
		}
		mod, err := probe.NewDNS(name, 1 /*A*/, spFirst, spLast, 255, conf.sendIPOnly)
		if err != nil {
			return nil, nil, err
		}
		return mod, p.Ports, nil
	case "upnp":
		portsStr := conf.targetPorts
		if portsStr == "" {
			portsStr = "1900"
		}
		p, err := ports.Parse(portsStr)
		if err != nil {
			return nil, nil, err
		}
		return probe.NewUPnP(spFirst, spLast, 255, conf.sendIPOnly), p.Ports, nil
	case "bacnet":
		portsStr := conf.targetPorts
		if portsStr == "" {
			portsStr = "47808"
		}
		p, err := ports.Parse(portsStr)
		if err != nil {
			return nil, nil, err
		}
		return probe.NewBACnet(spFirst, spLast, 255, conf.sendIPOnly), p.Ports, nil
	case "ipip":
		if conf.targetPorts == "" {
			return nil, nil, errors.New("ipip requires --target-ports")
		}
		p, err := ports.Parse(conf.targetPorts)
		if err != nil {
			return nil, nil, err
		}
		var payload []byte
		if strings.HasPrefix(conf.probeArgs, "text:") {
			payload = []byte(strings.TrimPrefix(conf.probeArgs, "text:"))
		}
		return probe.NewIPIP(payload, spFirst, spLast, 255, conf.sendIPOnly), p.Ports, nil
	}
	return nil, nil, fmt.Errorf("unknown probe module %q", conf.module)
}

func pickInterface(name string) (*net.Interface, error) {
	if name != "" {
		intf, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		return intf, nil
	}
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range intfs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() {
				return &i, nil
			}
		}
	}
	return nil, errors.New("could not auto-detect a non-loopback IPv4 interface; pass -i")
}

func pickSrcIP(intf *net.Interface, override string) (net.IP, error) {
	if override != "" {
		ip := net.ParseIP(override)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid --source-ip %q", override)
		}
		return ip.To4(), nil
	}
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", intf.Name)
}

func pickSrcMAC(intf *net.Interface, override string, ipOnly bool) (net.HardwareAddr, error) {
	if ipOnly {
		return nil, nil
	}
	if override != "" {
		m, err := net.ParseMAC(override)
		if err != nil {
			return nil, fmt.Errorf("--source-mac: %w", err)
		}
		return m, nil
	}
	if len(intf.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %s has no MAC; pass --source-mac", intf.Name)
	}
	return intf.HardwareAddr, nil
}

func resolveGatewayMAC(intf *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr,
	override string, conn raw.PacketConn, stderr io.Writer) (net.HardwareAddr, error) {
	if override != "" {
		m, err := net.ParseMAC(override)
		if err != nil {
			return nil, fmt.Errorf("--gateway-mac: %w", err)
		}
		return m, nil
	}
	gwIP, err := gateway.DefaultGateway(intf)
	if err != nil {
		return nil, fmt.Errorf("auto gateway detection failed: %w (use --gateway-mac or --send-ip-pkts)", err)
	}
	fmt.Fprintf(stderr, "zmap: resolving gateway %s via ARP on %s\n", gwIP, intf.Name)
	mac, err := gateway.ResolveMACWithConn(conn, srcIP, srcMAC, gwIP, 3*time.Second)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "zmap: gateway MAC %s -> %s\n", gwIP, mac)
	return mac, nil
}

func parseSrcPorts(s string) (uint16, uint16, error) {
	if s == "" {
		return 32768, 61000, nil
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		a, err1 := strconv.Atoi(s[:i])
		b, err2 := strconv.Atoi(s[i+1:])
		if err1 != nil || err2 != nil || a < 0 || b > 65535 || a > b {
			return 0, 0, fmt.Errorf("invalid --source-port %q", s)
		}
		return uint16(a), uint16(b), nil
	}
	a, err := strconv.Atoi(s)
	if err != nil || a < 0 || a > 65535 {
		return 0, 0, fmt.Errorf("invalid --source-port %q", s)
	}
	return uint16(a), uint16(a), nil
}

func parseMaxTargets(value string, portCount int) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	searchSpace := float64(uint64(1)<<32) * float64(portCount)
	text := strings.TrimSpace(value)
	percent := strings.HasSuffix(text, "%")
	if percent {
		text = strings.TrimSuffix(text, "%")
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid --max-targets")
	}
	if percent {
		parsed = parsed * searchSpace / 100
	}
	if parsed <= 0 {
		return 0, nil
	}
	if parsed >= searchSpace {
		return uint64(searchSpace), nil
	}
	return uint64(parsed), nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func parseArgs(args []string, stderr io.Writer) (options, error) {
	conf := options{verbosity: 3, shards: 1, cooldown: 8, rate: 10000, style: "windows", outputModule: "default"}
	flags := flag.NewFlagSet("zmap", flag.ContinueOnError)
	flags.SetOutput(stderr)

	str := func(p *string, names []string, def, usage string) {
		for _, n := range names {
			flags.StringVar(p, n, def, usage)
		}
	}
	intv := func(p *int, names []string, def int, usage string) {
		for _, n := range names {
			flags.IntVar(p, n, def, usage)
		}
	}
	boolv := func(p *bool, names []string, def bool, usage string) {
		for _, n := range names {
			flags.BoolVar(p, n, def, usage)
		}
	}
	u64v := func(p *uint64, names []string, usage string) {
		for _, n := range names {
			flags.Uint64Var(p, n, 0, usage)
		}
	}

	str(&conf.module, []string{"probe-module", "M"}, "tcp_synscan", "probe module")
	str(&conf.probeArgs, []string{"probe-args"}, "", "probe-specific args")
	str(&conf.targetPorts, []string{"target-ports", "p"}, "", "destination ports")
	str(&conf.blocklistFile, []string{"blocklist-file", "b"}, "", "blocklist file")
	str(&conf.allowlistFile, []string{"allowlist-file", "w"}, "", "allowlist file")
	str(&conf.outputFile, []string{"output-file", "o"}, "", "output file (- for stdout)")
	str(&conf.outputModule, []string{"output-module", "O"}, "default", "output module: default|csv|json")
	str(&conf.outputFields, []string{"output-fields", "f"}, "", "comma-delimited output fields")
	str(&conf.logFile, []string{"log-file", "l"}, "", "log file")
	str(&conf.iface, []string{"interface", "i"}, "", "network interface")
	str(&conf.srcIP, []string{"source-ip", "S"}, "", "source IP")
	str(&conf.srcMAC, []string{"source-mac"}, "", "source MAC")
	str(&conf.gwMAC, []string{"gateway-mac", "G"}, "", "gateway MAC (auto-detected if empty)")
	str(&conf.srcPortRange, []string{"source-port", "s"}, "", "source port or range")
	intv(&conf.rate, []string{"rate", "r"}, 10000, "send rate (pps, total)")
	str(&conf.maxTargets, []string{"max-targets", "n"}, "", "max targets to scan")
	intv(&conf.maxResults, []string{"max-results", "N"}, 0, "stop after N results")
	intv(&conf.maxRuntime, []string{"max-runtime", "t"}, 0, "stop after T seconds")
	intv(&conf.cooldown, []string{"cooldown-time", "c"}, 8, "post-send seconds to wait for replies")
	intv(&conf.verbosity, []string{"verbosity", "v"}, 3, "log verbosity")
	intv(&conf.senderThreads, []string{"sender-threads", "T"}, 0, "sender goroutines (default NumCPU-1)")
	boolv(&conf.dryrun, []string{"dryrun", "d"}, false, "do not send packets, write targets")
	boolv(&conf.sendIPOnly, []string{"send-ip-pkts"}, false, "skip Ethernet header on send")
	u64v(&conf.seed, []string{"seed", "e"}, "scan seed")
	intv(&conf.shards, []string{"shards"}, 1, "total shards")
	intv(&conf.shard, []string{"shard"}, 0, "this shard's index")
	boolv(&conf.versionFlag, []string{"version", "V"}, false, "print version")
	str(&conf.style, []string{"tcp-options"}, "windows", "TCP option set: windows|linux|bsd|smallest-probes")
	str(&conf.outputFilter, []string{"output-filter"}, "", "output filter expression (e.g. 'success = 1')")
	boolv(&conf.quiet, []string{"quiet", "q"}, false, "do not print live progress")
	boolv(&conf.noSummary, []string{"no-summary"}, false, "do not print final summary")
	intv(&conf.statusInterval, []string{"status-update-interval"}, 1, "seconds between status updates")

	if err := flags.Parse(args); err != nil {
		return conf, err
	}
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "seed", "e":
			conf.seedGiven = true
		case "shards":
			conf.shardsGiven = true
		case "shard":
			conf.shardGiven = true
		}
	})
	conf.destinations = flags.Args()
	return conf, nil
}
