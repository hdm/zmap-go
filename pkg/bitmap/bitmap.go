package bitmap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const (
	pageSizeBits  = 0x10000
	pageSizeBytes = pageSizeBits / 8
	pageMask      = 0xFFFF
)

type Bitmap []byte

func NewBitmap() Bitmap {
	return make(Bitmap, pageSizeBytes)
}

func (bm Bitmap) Check(value uint16) bool {
	pageIndex := value >> 3
	bitIndex := uint8(value & 0x07)
	return bm[pageIndex]&(1<<bitIndex) != 0
}

func (bm Bitmap) Set(value uint16) {
	pageIndex := value >> 3
	bitIndex := uint8(value & 0x07)
	bm[pageIndex] |= 1 << bitIndex
}

type Paged struct {
	pages [pageSizeBits]Bitmap
}

func NewPaged() *Paged {
	return &Paged{}
}

func (p *Paged) Check(value uint32) bool {
	top := value >> 16
	bottom := uint16(value & pageMask)
	return p.pages[top] != nil && p.pages[top].Check(bottom)
}

func (p *Paged) Set(value uint32) {
	top := uint16(value >> 16)
	bottom := uint16(value & pageMask)
	if p.pages[top] == nil {
		p.pages[top] = NewBitmap()
	}
	p.pages[top].Set(bottom)
}

func (p *Paged) LoadIPv4File(path string) (uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var count uint32
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil || !addr.Is4() {
			return count, fmt.Errorf("parse IPv4 address on line %d: %q", lineNumber, line)
		}
		p.Set(binary.BigEndian.Uint32(addr.AsSlice()))
		count++
	}
	return count, scanner.Err()
}
