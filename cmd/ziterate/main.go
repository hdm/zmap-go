package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/zmap/zmap/pkg/blocklist"
	"github.com/zmap/zmap/pkg/cyclic"
	"github.com/zmap/zmap/pkg/iterator"
	"github.com/zmap/zmap/pkg/ports"
	"github.com/zmap/zmap/pkg/shard"
)

const version = "DEVELOPMENT"

type options struct {
	targetPorts           string
	blocklistFile         string
	allowlistFile         string
	logFile               string
	verbosity             int
	ignoreBlocklistErrors bool
	seed                  uint64
	seedGiven             bool
	maxTargets            string
	disableSyslog         bool
	shards                int
	shardsGiven           bool
	shard                 int
	shardGiven            bool
	version               bool
	destinations          []string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "ziterate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	conf, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	if conf.version {
		fmt.Fprintf(stdout, "ziterate %s\n", version)
		return nil
	}
	if conf.logFile != "" {
		file, err := os.OpenFile(conf.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		_ = file.Close()
	}
	_ = conf.verbosity
	_ = conf.disableSyslog

	if (conf.shardGiven || conf.shardsGiven) && !conf.seedGiven {
		return fmt.Errorf("need to specify seed if sharding a scan")
	}
	if conf.shardGiven != conf.shardsGiven {
		return fmt.Errorf("need to specify both shard number and total number of shards")
	}
	if conf.shard < 0 || conf.shard > 65534 {
		return fmt.Errorf("argument `shard' must be between 0 and 65534")
	}
	if conf.shards < 1 || conf.shards > 65535 {
		return fmt.Errorf("argument `shards' must be between 1 and 65535")
	}
	if conf.shard >= conf.shards {
		return fmt.Errorf("with %d total shards, shard number (%d) must be in range [0, %d)", conf.shards, conf.shard, conf.shards)
	}

	portList := []uint16{0}
	if conf.targetPorts != "" {
		parsedPorts, err := ports.Parse(conf.targetPorts)
		if err != nil {
			return err
		}
		portList = parsedPorts.Ports
	}

	maxTargets, err := parseMaxTargets(conf.maxTargets, len(portList))
	if err != nil {
		return err
	}

	list, err := blocklist.New(blocklist.Config{
		AllowlistFile:    conf.allowlistFile,
		BlocklistFile:    conf.blocklistFile,
		AllowlistEntries: conf.destinations,
		IgnoreInvalid:    conf.ignoreBlocklistErrors,
	})
	if err != nil {
		return fmt.Errorf("initialize blocklist / allowlist: %w", err)
	}

	source := cyclic.Uint64Source(cyclic.SecureSource{})
	if conf.seedGiven {
		source = cyclic.NewSeedSource(conf.seed)
	}
	it, err := iterator.New(iterator.Config{
		NumThreads:  1,
		ShardIndex:  uint16(conf.shard),
		NumShards:   uint16(conf.shards),
		NumAddrs:    list.CountAllowed(),
		Ports:       portList,
		Source:      source,
		LookupIndex: list.LookupIndex,
	})
	if err != nil {
		return err
	}
	threadShard, err := it.Shard(0)
	if err != nil {
		return err
	}

	current, err := threadShard.CurrentTarget()
	if err != nil {
		return err
	}
	for count := uint64(0); current.Status == shard.OK; count++ {
		if maxTargets > 0 && count >= maxTargets {
			break
		}
		if current.Port != 0 {
			fmt.Fprintf(stdout, "%s,%d\n", current.IP, current.Port)
		} else {
			fmt.Fprintf(stdout, "%s\n", current.IP)
		}
		current, err = threadShard.NextTarget()
		if err != nil {
			return err
		}
	}
	return nil
}

func parseArgs(args []string, stderr io.Writer) (options, error) {
	conf := options{verbosity: 3, shards: 1}
	flags := flag.NewFlagSet("ziterate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&conf.targetPorts, "target-ports", "", "comma-delimited list of ports to scan")
	flags.StringVar(&conf.targetPorts, "p", "", "comma-delimited list of ports to scan")
	flags.StringVar(&conf.blocklistFile, "blocklist-file", "", "file of subnets to exclude")
	flags.StringVar(&conf.blocklistFile, "b", "", "file of subnets to exclude")
	flags.StringVar(&conf.allowlistFile, "allowlist-file", "", "file of subnets to include")
	flags.StringVar(&conf.allowlistFile, "w", "", "file of subnets to include")
	flags.StringVar(&conf.logFile, "log-file", "", "file to log to")
	flags.StringVar(&conf.logFile, "l", "", "file to log to")
	flags.IntVar(&conf.verbosity, "verbosity", 3, "set log level verbosity")
	flags.IntVar(&conf.verbosity, "v", 3, "set log level verbosity")
	flags.BoolVar(&conf.ignoreBlocklistErrors, "ignore-blocklist-errors", false, "ignore invalid blocklist/allowlist entries")
	flags.Uint64Var(&conf.seed, "seed", 0, "seed used to select address permutation")
	flags.Uint64Var(&conf.seed, "e", 0, "seed used to select address permutation")
	flags.StringVar(&conf.maxTargets, "max-targets", "", "cap number of targets to generate")
	flags.StringVar(&conf.maxTargets, "n", "", "cap number of targets to generate")
	flags.BoolVar(&conf.disableSyslog, "disable-syslog", false, "disable syslog logging")
	flags.IntVar(&conf.shards, "shards", 1, "total number of shards")
	flags.IntVar(&conf.shard, "shard", 0, "shard this scan is targeting")
	flags.BoolVar(&conf.version, "version", false, "print version and exit")
	flags.BoolVar(&conf.version, "V", false, "print version and exit")

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

func parseMaxTargets(value string, portCount int) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	if portCount <= 0 {
		return 0, fmt.Errorf("port count must be greater than zero")
	}
	searchSpace := float64(uint64(1)<<32) * float64(portCount)
	text := strings.TrimSpace(value)
	percent := strings.HasSuffix(text, "%")
	if percent {
		text = strings.TrimSuffix(text, "%")
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("can't convert max-targets to a number")
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
