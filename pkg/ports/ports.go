package ports

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zmap/zmap/pkg/bitmap"
)

type Config struct {
	Ports  []uint16
	bitmap bitmap.Bitmap
}

func Parse(definition string) (*Config, error) {
	definition = strings.TrimSpace(definition)
	if definition == "" {
		return nil, fmt.Errorf("empty port definition")
	}

	conf := &Config{bitmap: bitmap.NewBitmap()}
	if definition == "*" {
		conf.Ports = make([]uint16, 0, 1<<16)
		for port := 0; port <= 0xFFFF; port++ {
			conf.add(uint16(port))
		}
		return conf, nil
	}

	for _, part := range strings.Split(definition, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", definition)
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			first, err := parseOne(bounds[0])
			if err != nil {
				return nil, err
			}
			last, err := parseOne(bounds[1])
			if err != nil {
				return nil, err
			}
			if first > last {
				return nil, fmt.Errorf("invalid port range %d-%d", first, last)
			}
			for port := first; port <= last; port++ {
				conf.add(uint16(port))
			}
			continue
		}

		port, err := parseOne(part)
		if err != nil {
			return nil, err
		}
		conf.add(uint16(port))
	}
	return conf, nil
}

func (c *Config) Contains(port uint16) bool {
	return c.bitmap != nil && c.bitmap.Check(port)
}

func (c *Config) add(port uint16) {
	c.Ports = append(c.Ports, port)
	c.bitmap.Set(port)
}

func parseOne(value string) (int, error) {
	value = strings.TrimSpace(value)
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid target port %q", value)
	}
	if port < 0 || port > 0xFFFF {
		return 0, fmt.Errorf("invalid target port %d", port)
	}
	return port, nil
}
