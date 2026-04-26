package shard

import (
	"fmt"
	"math/big"
	"net/netip"

	"github.com/hdm/zmap-go/pkg/cyclic"
)

const (
	Done Status = iota
	OK
)

type Status uint8

type LookupIndexFunc func(index uint64) (netip.Addr, error)

type State struct {
	PacketsSent    uint64
	TargetsScanned uint64
	MaxTargets     uint64
	MaxPackets     uint64
	PacketsFailed  uint32
	FirstScanned   uint64
}

type Params struct {
	First   uint64
	Last    uint64
	Factor  uint64
	Modulus uint64
}

type Target struct {
	IP     netip.Addr
	Port   uint16
	Status Status
}

type Config struct {
	ShardIndex      uint16
	NumShards       uint16
	ThreadIndex     uint8
	NumThreads      uint8
	MaxTotalTargets uint64
	BitsForPort     uint8
	Cycle           cyclic.Cycle
	MaxIPIndex      uint64
	MaxTargetIndex  uint64
	Ports           []uint16
	LookupIndex     LookupIndexFunc
}

type Shard struct {
	State       State
	Params      Params
	current     uint64
	iterations  uint64
	threadID    uint8
	bitsForPort uint8
	maxIPIndex  uint64
	maxTarget   uint64
	ports       []uint16
	lookupIndex LookupIndexFunc
}

func New(config Config) (*Shard, error) {
	if config.NumShards == 0 {
		return nil, fmt.Errorf("number of shards must be greater than zero")
	}
	if config.NumThreads == 0 {
		return nil, fmt.Errorf("number of threads must be greater than zero")
	}
	if config.ShardIndex >= config.NumShards {
		return nil, fmt.Errorf("shard index %d out of range for %d shards", config.ShardIndex, config.NumShards)
	}
	if config.ThreadIndex >= config.NumThreads {
		return nil, fmt.Errorf("thread index %d out of range for %d threads", config.ThreadIndex, config.NumThreads)
	}
	if config.Cycle.Order == 0 || config.Cycle.Group.Prime == 0 || config.Cycle.Generator == 0 {
		return nil, fmt.Errorf("cycle must include group, order, and generator")
	}
	if len(config.Ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	if config.LookupIndex == nil {
		return nil, fmt.Errorf("lookup index function is required")
	}

	numSubshards := uint64(config.NumShards) * uint64(config.NumThreads)
	if numSubshards >= config.Cycle.Order {
		return nil, fmt.Errorf("%d subshards exceeds cycle order %d", numSubshards, config.Cycle.Order)
	}
	if config.MaxTotalTargets > 0 && numSubshards > config.MaxTotalTargets {
		return nil, fmt.Errorf("%d subshards exceeds max targets %d", numSubshards, config.MaxTotalTargets)
	}

	subIndex := uint64(config.ShardIndex)*uint64(config.NumThreads) + uint64(config.ThreadIndex)
	exponentBegin := (config.Cycle.Order / numSubshards) * subIndex
	exponentEnd := (config.Cycle.Order / numSubshards) * ((subIndex + 1) % numSubshards)
	exponentBegin = (exponentBegin + config.Cycle.Offset) % config.Cycle.Order
	exponentEnd = (exponentEnd + config.Cycle.Offset) % config.Cycle.Order

	s := &Shard{
		Params: Params{
			First:   powMod(config.Cycle.Generator, exponentBegin, config.Cycle.Group.Prime),
			Last:    powMod(config.Cycle.Generator, exponentEnd, config.Cycle.Group.Prime),
			Factor:  config.Cycle.Generator,
			Modulus: config.Cycle.Group.Prime,
		},
		threadID:    config.ThreadIndex,
		bitsForPort: config.BitsForPort,
		maxIPIndex:  config.MaxIPIndex,
		maxTarget:   config.MaxTargetIndex,
		ports:       append([]uint16(nil), config.Ports...),
		lookupIndex: config.LookupIndex,
	}
	s.current = s.Params.First
	if config.MaxTotalTargets > 0 {
		s.State.MaxTargets = config.MaxTotalTargets / numSubshards
		if subIndex < config.MaxTotalTargets%numSubshards {
			s.State.MaxTargets++
		}
	}
	if _, err := s.rollToValid(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Shard) CurrentTarget() (Target, error) {
	if s.current == 0 {
		return Target{Status: Done}, nil
	}
	return s.targetFromCandidate(s.current)
}

func (s *Shard) NextTarget() (Target, error) {
	if s.current == 0 {
		return Target{Status: Done}, nil
	}
	for {
		candidate := s.nextElement()
		if candidate == s.Params.Last {
			s.current = 0
			s.iterations++
			return Target{Status: Done}, nil
		}
		if candidate >= s.maxTarget {
			continue
		}
		ipIndex, portIndex := s.extract(candidate - 1)
		if ipIndex < s.maxIPIndex && uint64(portIndex) < uint64(len(s.ports)) {
			s.iterations++
			return s.targetFromParts(ipIndex, portIndex)
		}
	}
}

func (s *Shard) Iterations() uint64 {
	return s.iterations
}

func (s *Shard) ThreadID() uint8 {
	return s.threadID
}

func (s *Shard) CurrentElement() uint64 {
	return s.current
}

func (s *Shard) rollToValid() (Target, error) {
	if s.current == 0 {
		return Target{Status: Done}, nil
	}
	ipIndex, portIndex := s.extract(s.current - 1)
	if ipIndex < s.maxIPIndex && uint64(portIndex) < uint64(len(s.ports)) {
		return Target{Status: OK}, nil
	}
	return s.NextTarget()
}

func (s *Shard) nextElement() uint64 {
	s.current *= s.Params.Factor
	s.current %= s.Params.Modulus
	return s.current
}

func (s *Shard) targetFromCandidate(candidate uint64) (Target, error) {
	ipIndex, portIndex := s.extract(candidate - 1)
	if ipIndex >= s.maxIPIndex || uint64(portIndex) >= uint64(len(s.ports)) {
		return Target{Status: Done}, nil
	}
	return s.targetFromParts(ipIndex, portIndex)
}

func (s *Shard) targetFromParts(ipIndex uint64, portIndex uint16) (Target, error) {
	addr, err := s.lookupIndex(ipIndex)
	if err != nil {
		return Target{}, err
	}
	return Target{IP: addr, Port: s.ports[portIndex], Status: OK}, nil
}

func (s *Shard) extract(value uint64) (uint64, uint16) {
	portMask := uint64(1<<s.bitsForPort) - 1
	return value >> s.bitsForPort, uint16(value & portMask)
}

func powMod(base uint64, exponent uint64, modulus uint64) uint64 {
	return new(big.Int).Exp(
		new(big.Int).SetUint64(base),
		new(big.Int).SetUint64(exponent),
		new(big.Int).SetUint64(modulus),
	).Uint64()
}
