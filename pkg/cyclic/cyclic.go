package cyclic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

const maxPrimitiveRoot = uint64(1) << 22

type Group struct {
	Prime         uint64
	KnownPrimroot uint64
	PrimeFactors  []uint64
}

type Cycle struct {
	Group     Group
	Generator uint64
	Order     uint64
	Offset    uint64
}

type Uint64Source interface {
	Uint64() (uint64, error)
}

type SecureSource struct{}

type SeedSource struct {
	state uint64
}

func NewSeedSource(seed uint64) *SeedSource {
	return &SeedSource{state: seed}
}

func (SecureSource) Uint64() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func (s *SeedSource) Uint64() (uint64, error) {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31), nil
}

var groups = []Group{
	{Prime: 257, KnownPrimroot: 3, PrimeFactors: []uint64{2}},
	{Prime: 65537, KnownPrimroot: 3, PrimeFactors: []uint64{2}},
	{Prime: 16777259, KnownPrimroot: 2, PrimeFactors: []uint64{2, 23, 103, 3541}},
	{Prime: 268435459, KnownPrimroot: 2, PrimeFactors: []uint64{2, 3, 19, 87211}},
	{Prime: 4294967311, KnownPrimroot: 3, PrimeFactors: []uint64{2, 3, 5, 131, 364289}},
	{Prime: 8589934609, KnownPrimroot: 19, PrimeFactors: []uint64{2, 3, 59, 3033169}},
	{Prime: 17179869209, KnownPrimroot: 3, PrimeFactors: []uint64{2, 83, 1277, 20261}},
	{Prime: 68719476767, KnownPrimroot: 5, PrimeFactors: []uint64{2, 163, 883, 238727}},
	{Prime: 1099511627791, KnownPrimroot: 3, PrimeFactors: []uint64{2, 3, 5, 36650387593}},
	{Prime: 17592186044423, KnownPrimroot: 5, PrimeFactors: []uint64{2, 11, 53, 97, 155542661}},
	{Prime: 281474976710677, KnownPrimroot: 6, PrimeFactors: []uint64{2, 3, 7, 1361, 2462081249}},
}

func Groups() []Group {
	ret := make([]Group, len(groups))
	copy(ret, groups)
	for i := range ret {
		ret[i].PrimeFactors = append([]uint64(nil), ret[i].PrimeFactors...)
	}
	return ret
}

func GetGroup(minSize uint64) (Group, error) {
	for _, group := range groups {
		if group.Prime > minSize {
			group.PrimeFactors = append([]uint64(nil), group.PrimeFactors...)
			return group, nil
		}
	}
	return Group{}, fmt.Errorf("no cyclic group is larger than %d", minSize)
}

func MakeCycle(group Group, source Uint64Source) (Cycle, error) {
	if source == nil {
		source = SecureSource{}
	}
	generator, err := FindPrimitiveRoot(group, source)
	if err != nil {
		return Cycle{}, err
	}
	offset, err := source.Uint64()
	if err != nil {
		return Cycle{}, err
	}
	return Cycle{
		Group:     group,
		Generator: generator,
		Offset:    offset % group.Prime,
		Order:     group.Prime - 1,
	}, nil
}

func FindPrimitiveRoot(group Group, source Uint64Source) (uint64, error) {
	if group.Prime == 0 {
		return 0, fmt.Errorf("cyclic group prime must be non-zero")
	}
	if source == nil {
		source = SecureSource{}
	}
	word, err := source.Uint64()
	if err != nil {
		return 0, err
	}
	candidate := word % group.Prime
	for {
		candidate++
		candidate %= group.Prime
		candidate %= maxPrimitiveRoot
		if candidate == 0 {
			continue
		}
		if isPrimitiveRoot(candidate, group) {
			return candidate, nil
		}
	}
}

func isPrimitiveRoot(candidate uint64, group Group) bool {
	prime := new(big.Int).SetUint64(group.Prime)
	base := new(big.Int).SetUint64(candidate)
	for _, factor := range group.PrimeFactors {
		power := new(big.Int).SetUint64((group.Prime - 1) / factor)
		result := new(big.Int).Exp(base, power, prime)
		if result.Uint64() == 1 {
			return false
		}
	}
	return true
}
