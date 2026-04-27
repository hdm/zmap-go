//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package raw

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bsdConn implements raw L2 send and receive on the BSDs using BPF.
//
// Adapted from runzero/rawbsd (which is itself based on gopacket's
// bsdbpf), trimmed to the surface zmap needs.
type bsdConn struct {
	intf     *net.Interface
	fd       int
	device   string
	readBuf  []byte
	readLen  int
	consumed int
	link     string
	wordSize int
	closed   bool
	bufBytes int
}

func bpfWordAlign(x, ws int) int { return (x + (ws - 1)) &^ (ws - 1) }

func listenPacket(intf *net.Interface) (PacketConn, error) {
	c := &bsdConn{
		intf:     intf,
		bufBytes: 1024 * 1024,
		wordSize: int(unix.BPF_ALIGNMENT),
	}
	if err := c.openDevice(); err != nil {
		return nil, err
	}
	enable := 1
	if _, err := syscall.SetBpfBuflen(c.fd, c.bufBytes); err != nil {
		c.Close()
		return nil, fmt.Errorf("raw: SetBpfBuflen: %w", err)
	}
	c.readBuf = make([]byte, c.bufBytes)
	if err := syscall.SetBpfInterface(c.fd, intf.Name); err != nil {
		c.Close()
		return nil, fmt.Errorf("raw: SetBpfInterface: %w", err)
	}
	if err := syscall.SetBpfImmediate(c.fd, enable); err != nil {
		c.Close()
		return nil, fmt.Errorf("raw: SetBpfImmediate: %w", err)
	}
	if err := syscall.SetBpfHeadercmpl(c.fd, enable); err != nil {
		c.Close()
		return nil, fmt.Errorf("raw: SetBpfHeadercmpl: %w", err)
	}
	// inbound only (BIOCSSEESENT 0)
	dir := 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.fd), syscall.BIOCSSEESENT, uintptr(unsafe.Pointer(&dir))); errno != 0 {
		// non-fatal; some platforms differ
	}
	dlt, err := syscall.BpfDatalink(c.fd)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("raw: BpfDatalink: %w", err)
	}
	switch dlt {
	case syscall.DLT_EN10MB:
		c.link = "ethernet"
	case syscall.DLT_RAW:
		c.link = "raw"
	case syscall.DLT_NULL:
		c.link = "null"
	case syscall.DLT_LOOP:
		c.link = "loop"
	default:
		c.link = fmt.Sprintf("dlt-%d", dlt)
	}
	return c, nil
}

func (c *bsdConn) openDevice() error {
	for i := 0; i < 99; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(dev, syscall.O_RDWR, 0)
		if err == nil {
			c.fd = fd
			c.device = dev
			return nil
		}
	}
	return fmt.Errorf("raw: no usable /dev/bpf* device")
}

func (c *bsdConn) WriteTo(b []byte) (int, error) {
	return syscall.Write(c.fd, b)
}

func (c *bsdConn) ReadFrom(b []byte) (int, error) {
	for {
		if c.consumed >= c.readLen {
			c.consumed = 0
			n, err := syscall.Read(c.fd, c.readBuf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				c.readLen = 0
				return 0, err
			}
			if n == 0 {
				return 0, io.EOF
			}
			c.readLen = n
		}
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&c.readBuf[c.consumed]))
		frameStart := c.consumed + int(hdr.Hdrlen)
		c.consumed += bpfWordAlign(int(hdr.Hdrlen)+int(hdr.Caplen), c.wordSize)
		if frameStart+int(hdr.Caplen) > len(c.readBuf) {
			return 0, io.ErrShortBuffer
		}
		frame := c.readBuf[frameStart : frameStart+int(hdr.Caplen)]
		n := copy(b, frame)
		return n, nil
	}
}

func (c *bsdConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return syscall.Close(c.fd)
}

func (c *bsdConn) Interface() *net.Interface { return c.intf }
func (c *bsdConn) LinkType() string          { return c.link }

// bsdSender is a per-thread BPF transmit handle. Each sender owns its own
// /dev/bpf* fd to avoid contention on the receive fd when many sender
// goroutines run in parallel.
type bsdSender struct {
	fd     int
	closed bool
}

func (c *bsdConn) NewSender() (Sender, error) {
	var fd int
	var dev string
	for i := 0; i < 99; i++ {
		d := fmt.Sprintf("/dev/bpf%d", i)
		f, err := syscall.Open(d, syscall.O_RDWR, 0)
		if err == nil {
			fd = f
			dev = d
			break
		}
	}
	if dev == "" {
		// fall back to sharing the read fd if we can't grab another one
		return &bsdSender{fd: c.fd, closed: true}, nil
	}
	if err := syscall.SetBpfInterface(fd, c.intf.Name); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("raw: sender SetBpfInterface: %w", err)
	}
	if err := syscall.SetBpfHeadercmpl(fd, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("raw: sender SetBpfHeadercmpl: %w", err)
	}
	return &bsdSender{fd: fd}, nil
}

func (s *bsdSender) WriteTo(b []byte) (int, error) {
	return syscall.Write(s.fd, b)
}

// WriteBatch loops over WriteTo. BPF on the BSDs has no native batch send
// equivalent to Linux's sendmmsg(2); the per-thread fd already removes the
// shared-lock bottleneck, which is the primary scaling win on these
// platforms.
func (s *bsdSender) WriteBatch(pkts [][]byte) (int, error) {
	for i, p := range pkts {
		if _, err := syscall.Write(s.fd, p); err != nil {
			return i, err
		}
	}
	return len(pkts), nil
}

func (s *bsdSender) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return syscall.Close(s.fd)
}

// keep imports referenced even if unused on some BSDs
var (
	_ = os.Getpid
	_ = time.Now
)
