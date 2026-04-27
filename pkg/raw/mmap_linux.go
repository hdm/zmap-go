//go:build linux

package raw

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PACKET_MMAP TX ring (TPACKET_V2) sender.
//
// The standard sendmmsg(2) sender copies every frame from userspace into a
// freshly-allocated kernel skb on each syscall. At the rates we're chasing
// the syscall trap and the per-packet skb alloc dominate the profile.
//
// PACKET_MMAP gives us a shared ring buffer between user and kernel: we
// write the frame bytes directly into a slot in the mmap'd ring, flip the
// status word, and a single send(2) tells the kernel to drain everything
// currently marked SEND_REQUEST. There is no per-frame copy and only one
// syscall per drain regardless of how many frames are pending.
//
// This implementation is opt-in via PreferTxRing because:
//   - it wastes ~frame_size bytes per slot (we allocate worst-case 2 KiB
//     slots even for our 60-byte SYN frames),
//   - some kernels / drivers handle TPACKET TX poorly under contention,
//   - it requires CAP_NET_RAW + the ability to mmap a few MiB, which may
//     fail in tight cgroup environments.
//
// Layout reference: Documentation/networking/packet_mmap.rst.

const (
	// setsockopt names (from <linux/if_packet.h>).
	packetVersion    = 10
	packetTxRing     = 13
	packetQdiscBypas = 20

	tpacketV2 = 1

	// tpacket2_hdr.tp_status values.
	tpStatusAvailable   = 0
	tpStatusSendRequest = 1
	tpStatusSending     = 2
	tpStatusWrongFormat = 4

	// sizeof(struct tpacket2_hdr) = 32; TPACKET2_HDRLEN adds
	// sizeof(struct sockaddr_ll) = 20 → 52, then we round to 16 → 64.
	// Frame data starts at this offset within each ring slot.
	tpacket2HdrLen   = 32
	tpacketSockaddr  = 20
	tpacketAlignment = 16
)

func tpacketAlign(x int) int {
	return (x + tpacketAlignment - 1) &^ (tpacketAlignment - 1)
}

// Frame data offset inside a ring slot.
var frameDataOffset = tpacketAlign(tpacket2HdrLen + tpacketSockaddr) // 64

// Ring sizing. block_size must be a multiple of PAGE_SIZE and a multiple of
// frame_size; frame_nr = block_nr * (block_size / frame_size). 4 MiB total
// gives us 2048 frames at 2 KiB each — well in excess of the burst we need
// to absorb between drain syscalls, while staying small enough to avoid
// noticeable RSS impact per sender goroutine.
const (
	mmapBlockSize  = 1 << 22 // 4 MiB
	mmapFrameSize  = 2048
	mmapBlockNr    = 1
	mmapFrameNr    = mmapBlockNr * (mmapBlockSize / mmapFrameSize)
	mmapRingBytes  = mmapBlockNr * mmapBlockSize
	mmapMaxPayload = mmapFrameSize - 64 // frameDataOffset
)

// tpacketReq mirrors struct tpacket_req. The kernel reads exactly 16 bytes.
type tpacketReq struct {
	BlockSize uint32
	BlockNr   uint32
	FrameSize uint32
	FrameNr   uint32
}

type mmapSender struct {
	fd     int
	ring   []byte
	head   int // next slot to fill
	closed bool
}

// newMmapSender attempts to allocate a TPACKET_V2 TX ring on a fresh
// AF_PACKET socket. Returns an error on any kernel rejection so the caller
// can fall back to sendmmsg.
func newMmapSender(intf *net.Interface) (*mmapSender, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("raw: tx ring socket: %w", err)
	}
	cleanup := func() { unix.Close(fd) }
	// Must select TPACKET version *before* requesting the ring.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, packetVersion, tpacketV2); err != nil {
		cleanup()
		return nil, fmt.Errorf("raw: PACKET_VERSION=TPACKET_V2: %w", err)
	}
	req := tpacketReq{
		BlockSize: mmapBlockSize,
		BlockNr:   mmapBlockNr,
		FrameSize: mmapFrameSize,
		FrameNr:   mmapFrameNr,
	}
	// unix package has no helper for PACKET_TX_RING; raw setsockopt(2).
	_, _, errno := syscall.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_PACKET),
		uintptr(packetTxRing),
		uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req),
		0,
	)
	if errno != 0 {
		cleanup()
		return nil, fmt.Errorf("raw: PACKET_TX_RING: %w", errno)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  intf.Index,
	}); err != nil {
		cleanup()
		return nil, fmt.Errorf("raw: tx ring bind: %w", err)
	}
	// Best-effort qdisc bypass — same rationale as the sendmmsg path.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetQdiscBypas, 1)
	ring, err := unix.Mmap(fd, 0, mmapRingBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_LOCKED|unix.MAP_POPULATE)
	if err != nil {
		// MAP_LOCKED requires CAP_IPC_LOCK on some kernels / RLIMIT_MEMLOCK
		// headroom; retry without it before giving up.
		ring, err = unix.Mmap(fd, 0, mmapRingBytes,
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("raw: mmap tx ring: %w", err)
		}
	}
	s := &mmapSender{fd: fd, ring: ring}
	runtime.SetFinalizer(s, func(s *mmapSender) { _ = s.Close() })
	return s, nil
}

func (s *mmapSender) slot(i int) []byte {
	off := i * mmapFrameSize
	return s.ring[off : off+mmapFrameSize]
}

// statusOf returns an atomic pointer to the tp_status field at the head of
// slot i. The kernel reads/writes this word with release/acquire semantics
// so we mirror that in userspace.
func (s *mmapSender) statusOf(i int) *uint32 {
	return (*uint32)(unsafe.Pointer(&s.ring[i*mmapFrameSize]))
}

// queueOne writes one frame into the next available slot. Returns false if
// the slot is still owned by the kernel (ring full).
func (s *mmapSender) queueOne(p []byte) bool {
	if len(p) == 0 || len(p) > mmapMaxPayload {
		// Zero-len frames have no useful semantics here; oversized frames
		// would corrupt the next slot. Drop silently — the caller's failed
		// counter will reflect it.
		return false
	}
	statusPtr := s.statusOf(s.head)
	if atomic.LoadUint32(statusPtr) != tpStatusAvailable {
		return false
	}
	slot := s.slot(s.head)
	// tp_len at offset 4, tp_snaplen at offset 8.
	*(*uint32)(unsafe.Pointer(&slot[4])) = uint32(len(p))
	*(*uint32)(unsafe.Pointer(&slot[8])) = uint32(len(p))
	copy(slot[frameDataOffset:], p)
	atomic.StoreUint32(statusPtr, tpStatusSendRequest)
	s.head++
	if s.head >= mmapFrameNr {
		s.head = 0
	}
	return true
}

// flush kicks the kernel to drain everything currently marked SEND_REQUEST.
// MSG_DONTWAIT means the syscall returns as soon as the kernel has queued
// the work; the actual TX completes asynchronously and the kernel flips
// each slot's status back to AVAILABLE when its frame leaves the NIC.
func (s *mmapSender) flush() error {
	_, _, errno := syscall.Syscall6(
		unix.SYS_SENDTO,
		uintptr(s.fd),
		0, 0, // buf=NULL, len=0
		uintptr(unix.MSG_DONTWAIT),
		0, 0,
	)
	if errno == 0 || errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
		return nil
	}
	return errno
}

func (s *mmapSender) WriteTo(b []byte) (int, error) {
	for !s.queueOne(b) {
		if err := s.flush(); err != nil {
			return 0, err
		}
		// Briefly yield while the kernel drains the head slot.
		runtime.Gosched()
	}
	if err := s.flush(); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteBatch matches the contract of linuxSender.WriteBatch: queue as many
// frames as the ring will currently accept, kick the kernel once, return
// the count actually queued. The caller's partial-send retry loop handles
// re-feeding the unaccepted tail.
func (s *mmapSender) WriteBatch(pkts [][]byte) (int, error) {
	count := 0
	for _, p := range pkts {
		if !s.queueOne(p) {
			break
		}
		count++
	}
	if count == 0 {
		// Ring is full — drain whatever the kernel has finished and tell
		// the caller to back off briefly.
		_ = s.flush()
		return 0, unix.EAGAIN
	}
	if err := s.flush(); err != nil {
		return count, err
	}
	return count, nil
}

func (s *mmapSender) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.ring != nil {
		_ = unix.Munmap(s.ring)
		s.ring = nil
	}
	if s.fd >= 0 {
		err := unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

// (file-local helper to silence unused-import on platforms that drop os.)
var _ = os.NewFile
