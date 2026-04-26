package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "DEVELOPMENT"

type format int

const (
	formatRaw format = iota
	formatCSV
	formatJSON
)

func (f format) String() string {
	switch f {
	case formatCSV:
		return "csv"
	case formatJSON:
		return "json"
	default:
		return "raw"
	}
}

type options struct {
	successOnly       bool
	monitor           bool
	statusUpdatesFile string
	logFile           string
	raw               bool
	version           bool
	output            string
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "ztee: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	conf, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	if conf.version {
		fmt.Fprintf(stdout, "ztee %s\n", version)
		return nil
	}
	if conf.output == "" {
		return errors.New("no output file specified")
	}

	outputFile, err := os.Create(conf.output)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer outputFile.Close()

	var statusFile io.Writer
	if conf.statusUpdatesFile != "" {
		file, err := os.Create(conf.statusUpdatesFile)
		if err != nil {
			return fmt.Errorf("open status updates file: %w", err)
		}
		defer file.Close()
		statusFile = file
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		return nil
	}
	first := scanner.Text()
	inputFormat := formatRaw
	if !conf.raw {
		inputFormat = detectFormat(first)
	}
	if inputFormat == formatJSON {
		return errors.New("json input not implemented")
	}

	ipField, successField := -1, -1
	if inputFormat == formatCSV {
		ipField, successField = csvHeaderFields(first)
		if ipField < 0 {
			return errors.New("unable to find IP/SADDR field")
		}
		if conf.successOnly && successField < 0 {
			return errors.New("could not find success field")
		}
	} else if conf.successOnly {
		return errors.New("success filter requires csv input")
	}

	output := bufio.NewWriter(outputFile)
	defer output.Flush()
	stdoutBuf := bufio.NewWriter(stdout)
	defer stdoutBuf.Flush()

	totalRead := 0
	totalWritten := 0
	process := func(line string) error {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		totalRead++
		switch inputFormat {
		case formatCSV:
			if totalWritten == 0 {
				totalWritten++
				return nil
			}
			fields, err := parseCSVRow(line)
			if err != nil {
				totalWritten++
				return nil
			}
			if conf.successOnly && !rowIsSuccessful(fields, successField) {
				totalWritten++
				return nil
			}
			if ipField >= 0 && ipField < len(fields) {
				if _, err := fmt.Fprintln(stdoutBuf, fields[ipField]); err != nil {
					return err
				}
			}
		default:
			if _, err := fmt.Fprintln(stdoutBuf, line); err != nil {
				return err
			}
		}
		totalWritten++
		return nil
	}

	if err := process(first); err != nil {
		return err
	}
	for scanner.Scan() {
		if err := process(scanner.Text()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if statusFile != nil {
		fmt.Fprintf(statusFile, "time_past,total_read_in,read_in_last_sec,read_per_sec_avg,buffer_current_size,buffer_avg_size\n")
		fmt.Fprintf(statusFile, "%d,%d,%d,%d,%d,%d\n", 0, totalRead, totalRead, totalRead, 0, 0)
	}
	if conf.monitor {
		fmt.Fprintf(stderr, "ztee: processed %d rows\n", totalRead)
	}
	return nil
}

func parseArgs(args []string, stderr io.Writer) (options, error) {
	conf := options{}
	flags := flag.NewFlagSet("ztee", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&conf.successOnly, "success-only", false, "only write rows where success=1 or success=true to stdout")
	flags.BoolVar(&conf.monitor, "monitor", false, "print summary monitor data to stderr at end")
	flags.BoolVar(&conf.monitor, "m", false, "print summary monitor data to stderr at end")
	flags.StringVar(&conf.statusUpdatesFile, "status-updates-file", "", "file to write status updates to")
	flags.StringVar(&conf.statusUpdatesFile, "u", "", "file to write status updates to")
	flags.StringVar(&conf.logFile, "log-file", "", "file to log errors to")
	flags.StringVar(&conf.logFile, "l", "", "file to log errors to")
	flags.BoolVar(&conf.raw, "raw", false, "ignore input formatting and pass through raw input")
	flags.BoolVar(&conf.raw, "r", false, "ignore input formatting and pass through raw input")
	flags.BoolVar(&conf.version, "version", false, "print version and exit")
	flags.BoolVar(&conf.version, "V", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return conf, err
	}
	if flags.NArg() > 1 {
		return conf, fmt.Errorf("extra positional arguments starting with %s", flags.Args()[1])
	}
	if flags.NArg() == 1 {
		conf.output = flags.Args()[0]
	}
	return conf, nil
}

func detectFormat(line string) format {
	if len(line) >= 2 && line[0] == '{' && line[len(line)-1] == '}' {
		return formatJSON
	}
	if strings.Contains(line, ",") {
		return formatCSV
	}
	return formatRaw
}

func csvHeaderFields(header string) (ipField, successField int) {
	ipField, successField = -1, -1
	fields, err := parseCSVRow(header)
	if err != nil {
		return -1, -1
	}
	for index, name := range fields {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "saddr":
			ipField = index
		case "ip":
			if ipField < 0 {
				ipField = index
			}
		case "success":
			successField = index
		}
	}
	return ipField, successField
}

func parseCSVRow(line string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.FieldsPerRecord = -1
	return reader.Read()
}

func rowIsSuccessful(fields []string, successField int) bool {
	if successField < 0 || successField >= len(fields) {
		return false
	}
	value := strings.TrimSpace(fields[successField])
	switch strings.ToLower(value) {
	case "1", "true":
		return true
	}
	return false
}
