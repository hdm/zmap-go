package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/hdm/zmap-go/pkg/bitmap"
	"github.com/hdm/zmap-go/pkg/blocklist"
)

const (
	version    = "DEVELOPMENT"
	maxLineLen = 1024*1024 + 2
)

type options struct {
	blocklistFile         string
	allowlistFile         string
	logFile               string
	verbosity             int
	noDuplicateChecking   bool
	ignoreBlocklistErrors bool
	ignoreInputErrors     bool
	disableSyslog         bool
	version               bool
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "zblocklist: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	conf, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	if conf.version {
		fmt.Fprintf(stdout, "zblocklist %s\n", version)
		return nil
	}
	if conf.blocklistFile == "" && conf.allowlistFile == "" {
		return fmt.Errorf("must specify either an allowlist or blocklist file")
	}

	list, err := blocklist.New(blocklist.Config{
		AllowlistFile: conf.allowlistFile,
		BlocklistFile: conf.blocklistFile,
		IgnoreInvalid: conf.ignoreBlocklistErrors,
	})
	if err != nil {
		return fmt.Errorf("initialize blocklist / allowlist: %w", err)
	}

	var seen *bitmap.Paged
	if !conf.noDuplicateChecking {
		seen = bitmap.NewPaged()
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), maxLineLen)
	out := bufio.NewWriter(stdout)
	defer out.Flush()

	for scanner.Scan() {
		raw := scanner.Text()
		token := firstToken(raw)
		if token == "" {
			continue
		}
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.Is4() {
			fmt.Fprintf(stderr, "zblocklist: invalid input address: %s\n", token)
			if !conf.ignoreInputErrors {
				if _, err := fmt.Fprintln(out, raw); err != nil {
					return err
				}
			}
			continue
		}
		if seen != nil && seen.Check(ipv4ToUint32(addr)) {
			continue
		}
		if !list.IsAllowed(addr) {
			continue
		}
		if seen != nil {
			seen.Set(ipv4ToUint32(addr))
		}
		if _, err := fmt.Fprintln(out, raw); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func parseArgs(args []string, stderr io.Writer) (options, error) {
	conf := options{verbosity: 3}
	flags := flag.NewFlagSet("zblocklist", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&conf.blocklistFile, "blocklist-file", "", "file of subnets to exclude")
	flags.StringVar(&conf.blocklistFile, "b", "", "file of subnets to exclude")
	flags.StringVar(&conf.allowlistFile, "allowlist-file", "", "file of subnets to include")
	flags.StringVar(&conf.allowlistFile, "w", "", "file of subnets to include")
	flags.StringVar(&conf.logFile, "log-file", "", "file to log to")
	flags.StringVar(&conf.logFile, "l", "", "file to log to")
	flags.IntVar(&conf.verbosity, "verbosity", 3, "set log level verbosity")
	flags.IntVar(&conf.verbosity, "v", 3, "set log level verbosity")
	flags.BoolVar(&conf.noDuplicateChecking, "no-duplicate-checking", false, "do not deduplicate IP addresses")
	flags.BoolVar(&conf.ignoreBlocklistErrors, "ignore-blocklist-errors", false, "ignore invalid blocklist/allowlist entries")
	flags.BoolVar(&conf.ignoreInputErrors, "ignore-input-errors", false, "do not print invalid input entries")
	flags.BoolVar(&conf.disableSyslog, "disable-syslog", false, "disable syslog logging")
	flags.BoolVar(&conf.version, "version", false, "print version and exit")
	flags.BoolVar(&conf.version, "V", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return conf, err
	}
	if flags.NArg() > 0 {
		return conf, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	return conf, nil
}

func firstToken(line string) string {
	for i, r := range line {
		switch r {
		case ',', '\t', ' ', '#':
			return line[:i]
		}
	}
	return strings.TrimRight(line, "\r")
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
