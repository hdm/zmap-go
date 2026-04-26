package iterator

import (
	"fmt"
	"math/bits"
	"net/netip"

	"github.com/zmap/zmap/pkg/cyclic"
	"github.com/zmap/zmap/pkg/shard"
)

type LookupIndexFunc func(index uint64) (netip.Addr, error)

type Config struct {
	NumThreads      uint8
	ShardIndex      uint16
	NumShards       uint16
	NumAddrs        uint64
	Ports           []uint16
	MaxTotalTargets uint64
	Source          cyclic.Uint64Source
	LookupIndex     LookupIndexFunc
}

type Iterator struct {
	Cycle       cyclic.Cycle
	shards      []*shard.Shard
	bitsForIP   uint8
	bitsForPort uint8
}

func New(config Config) (*Iterator, error) {
	if config.NumThreads == 0 {
		return nil, fmt.Errorf("number of threads must be greater than zero")
	}
	if config.NumAddrs == 0 {
		return nil, fmt.Errorf("number of addresses must be greater than zero")
	}
	if len(config.Ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	if config.LookupIndex == nil {
		return nil, fmt.Errorf("lookup index function is required")
	}

	bitsForIP := bitsNeeded(config.NumAddrs)
	bitsForPort := bitsNeeded(uint64(len(config.Ports)))
	groupMinSize := uint64(1) << (bitsForIP + bitsForPort)
	group, err := cyclic.GetGroup(groupMinSize)
	if err != nil {
		return nil, err
	}
	cycle, err := cyclic.MakeCycle(group, config.Source)
	if err != nil {
		return nil, err
	}

	maxIPIndex := config.NumAddrs
	if config.NumAddrs > 1<<32 {
		maxIPIndex = 0xFFFFFFFF
	}
	maxTargetIndex := uint64(1) << (32 + bitsForPort)

	it := &Iterator{
		Cycle:       cycle,
		shards:      make([]*shard.Shard, config.NumThreads),
		bitsForIP:   bitsForIP,
		bitsForPort: bitsForPort,
	}
	for i := uint8(0); i < config.NumThreads; i++ {
		threadShard, err := shard.New(shard.Config{
			ShardIndex:      config.ShardIndex,
			NumShards:       config.NumShards,
			ThreadIndex:     i,
			NumThreads:      config.NumThreads,
			MaxTotalTargets: config.MaxTotalTargets,
			BitsForPort:     bitsForPort,
			Cycle:           cycle,
			MaxIPIndex:      maxIPIndex,
			MaxTargetIndex:  maxTargetIndex,
			Ports:           config.Ports,
			LookupIndex:     shard.LookupIndexFunc(config.LookupIndex),
		})
		if err != nil {
			return nil, err
		}
		it.shards[i] = threadShard
	}
	return it, nil
}

func (it *Iterator) Shard(threadID uint8) (*shard.Shard, error) {
	if int(threadID) >= len(it.shards) {
		return nil, fmt.Errorf("thread id %d out of range", threadID)
	}
	return it.shards[threadID], nil
}

func (it *Iterator) Iterations() uint64 {
	var total uint64
	for _, s := range it.shards {
		total += s.Iterations()
	}
	return total
}

func (it *Iterator) BitsForIP() uint8 {
	return it.bitsForIP
}

func (it *Iterator) BitsForPort() uint8 {
	return it.bitsForPort
}

func bitsNeeded(n uint64) uint8 {
	if n <= 1 {
		return 0
	}
	return uint8(bits.Len64(n - 1))
}
