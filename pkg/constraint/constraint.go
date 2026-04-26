package constraint

import "fmt"

type Value uint32

const radixLength = 18

const radixChunk = uint64(1) << (32 - radixLength)

type node struct {
	left  *node
	right *node
	value Value
	count uint64
}

type Constraint struct {
	root       *node
	radix      []uint32
	painted    bool
	paintValue Value
}

func New(defaultValue Value) *Constraint {
	return &Constraint{
		root:  newLeaf(defaultValue),
		radix: make([]uint32, 0, 1<<radixLength),
	}
}

func (c *Constraint) Set(prefix uint32, length int, value Value) error {
	if length < 0 || length > 32 {
		return fmt.Errorf("invalid IPv4 prefix length %d", length)
	}
	setRecurse(c.root, prefix, length, value)
	c.painted = false
	return nil
}

func (c *Constraint) Lookup(address uint32) Value {
	current := c.root
	mask := uint32(0x80000000)
	for {
		if current.isLeaf() {
			return current.value
		}
		if address&mask != 0 {
			current = current.right
		} else {
			current = current.left
		}
		mask >>= 1
	}
}

func (c *Constraint) Count(value Value) uint64 {
	if c.painted && c.paintValue == value {
		return c.root.count + uint64(len(c.radix))*radixChunk
	}
	return countRecurse(c.root, value, uint64(1)<<32, false, false)
}

func (c *Constraint) Paint(value Value) {
	countRecurse(c.root, value, uint64(1)<<32, true, true)
	c.radix = c.radix[:0]
	for i := uint32(0); i < 1<<radixLength; i++ {
		prefix := i << (32 - radixLength)
		n := lookupNode(c.root, prefix, radixLength)
		if n.isLeaf() && n.value == value {
			c.radix = append(c.radix, prefix)
		}
	}
	c.painted = true
	c.paintValue = value
}

func (c *Constraint) LookupIndex(index uint64, value Value) (uint32, error) {
	if !c.painted || c.paintValue != value {
		c.Paint(value)
	}
	count := c.root.count + uint64(len(c.radix))*radixChunk
	if index >= count {
		return 0, fmt.Errorf("index %d out of range for %d matching addresses", index, count)
	}
	radixIndex := index / radixChunk
	if radixIndex < uint64(len(c.radix)) {
		radixOffset := uint32(index % radixChunk)
		return c.radix[radixIndex] | radixOffset, nil
	}
	index -= uint64(len(c.radix)) * radixChunk
	return lookupIndex(c.root, index), nil
}

func newLeaf(value Value) *node {
	return &node{value: value}
}

func (n *node) isLeaf() bool {
	return n.left == nil
}

func (n *node) convertToLeaf() {
	n.left = nil
	n.right = nil
}

func setRecurse(n *node, prefix uint32, length int, value Value) {
	if length == 0 {
		n.convertToLeaf()
		n.value = value
		return
	}
	if n.isLeaf() {
		if n.value == value {
			return
		}
		n.left = newLeaf(n.value)
		n.right = newLeaf(n.value)
	}
	if prefix&0x80000000 != 0 {
		setRecurse(n.right, prefix<<1, length-1, value)
	} else {
		setRecurse(n.left, prefix<<1, length-1, value)
	}
	if n.left.isLeaf() && n.right.isLeaf() && n.left.value == n.right.value {
		n.value = n.left.value
		n.convertToLeaf()
	}
}

func lookupIndex(root *node, index uint64) uint32 {
	current := root
	var ip uint32
	mask := uint32(0x80000000)
	for {
		if current.isLeaf() {
			return ip | uint32(index)
		}
		if index < current.left.count {
			current = current.left
		} else {
			index -= current.left.count
			current = current.right
			ip |= mask
		}
		mask >>= 1
	}
}

func countRecurse(n *node, value Value, size uint64, paint bool, excludeRadix bool) uint64 {
	var count uint64
	if n.isLeaf() {
		if n.value == value {
			count = size
			if excludeRadix && size >= radixChunk {
				count = 0
			}
		}
	} else {
		count = countRecurse(n.left, value, size>>1, paint, excludeRadix) +
			countRecurse(n.right, value, size>>1, paint, excludeRadix)
	}
	if paint {
		n.count = count
	}
	return count
}

func lookupNode(root *node, prefix uint32, length int) *node {
	current := root
	mask := uint32(0x80000000)
	for i := 0; i < length; i++ {
		if current.isLeaf() {
			return current
		}
		if prefix&mask != 0 {
			current = current.right
		} else {
			current = current.left
		}
		mask >>= 1
	}
	return current
}
