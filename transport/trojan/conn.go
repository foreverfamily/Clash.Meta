package trojan

import (
	"bytes"
	"fmt"
	"github.com/Dreamacro/clash/log"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

type muxConn struct {
	net.Conn //outconn
	synQueue chan []byte
	finQueue chan []byte
}

func newMuxConn(conn net.Conn) *muxConn {
	return &muxConn{
		Conn:     conn,
		synQueue: make(chan []byte, 128),
		finQueue: make(chan []byte, 128),
	}
}

func (c *muxConn) stickToPayload(p []byte) []byte {
	buf := make([]byte, 0, len(p)+16)
	for {
		select {
		case header := <-c.synQueue:
			buf = append(buf, header...)
		default:
			goto stick1
		}
	}
stick1:
	buf = append(buf, p...)
	for {
		select {
		case header := <-c.finQueue:
			buf = append(buf, header...)
		default:
			goto stick2
		}
	}
stick2:
	return buf
}

func (c *muxConn) Close() error {
	const maxPaddingLength = 512
	padding := [maxPaddingLength + 8]byte{'A', 'B', 'C', 'D', 'E', 'F'} // for debugging
	buf := c.stickToPayload(nil)
	c.Write(append(buf, padding[:rand.Intn(maxPaddingLength)]...))
	return c.Conn.Close()
}

func (c *muxConn) Write(p []byte) (int, error) {
	if len(p) == 8 {
		if p[0] == 1 || p[0] == 2 { // smux 8 bytes header
			switch p[1] {
			// THE CONTENT OF THE BUFFER MIGHT CHANGE
			// NEVER STORE THE POINTER TO HEADER, COPY THE HEADER INSTEAD
			case 0:
				// cmdSYN
				header := make([]byte, 8)
				copy(header, p)
				c.synQueue <- header
				return 8, nil
			case 1:
				// cmdFIN
				header := make([]byte, 8)
				copy(header, p)
				c.finQueue <- header
				return 8, nil
			}
		} else {
			fmt.Println("other 8 bytes header")
		}
	}
	_, err := c.Conn.Write(c.stickToPayload(p))
	return len(p), err
}

type streamMuxConn struct {
	rwc      io.ReadWriteCloser // stream
	net.Conn                    //wscon or httpscon
}

func (c *streamMuxConn) Read(p []byte) (int, error) {
	return c.rwc.Read(p)
}

func (c *streamMuxConn) Write(p []byte) (int, error) {
	return c.rwc.Write(p)
}

func (c *streamMuxConn) Close() error {
	return c.rwc.Close()
}

const (
	MaxPacketSize = 1024 * 8
)

type OutboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	metadata          *Metadata
	hexPassword       []byte
	headerWrittenOnce sync.Once
	net.Conn          //ws or httpsconn
}

func (c *OutboundConn) Metadata() *Metadata {
	return c.metadata
}

func (c *OutboundConn) WriteHeader() (bool, error) {
	var err error
	written := false
	c.headerWrittenOnce.Do(func() {
		hash := c.hexPassword
		buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
		crlf := []byte{0x0d, 0x0a}
		buf.Write([]byte(hash))
		buf.Write(crlf)
		c.metadata.WriteTo(buf)
		buf.Write(crlf)
		_, err = c.Conn.Write(buf.Bytes())
		if err == nil {
			written = true
		}
	})
	return written, err
}

func (c *OutboundConn) Write(p []byte) (int, error) {
	_, err := c.WriteHeader()
	if err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	return n, err
}

func (c *OutboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	return n, err
}

func (c *OutboundConn) Close() error {
	log.Infoln("closed: connection to %+v, sent:%s, recv: %s", c.metadata, HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	return c.Conn.Close()
}

type MuxConfig struct {
	Enabled     bool `proxy:"enabled" yaml:"enabled"`
	IdleTimeout int  `proxy:"idle-timeout" yaml:"idle-timeout"`
	Concurrency int  `proxy:"concurrency" yaml:"concurrency"`
	Parallel    int  `proxy:"parallel" yaml:"parallel"`
}

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024
)

func HumanFriendlyTraffic(bytes uint64) string {
	if bytes <= KiB {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes <= MiB {
		return fmt.Sprintf("%.2f KiB", float32(bytes)/KiB)
	}
	if bytes <= GiB {
		return fmt.Sprintf("%.2f MiB", float32(bytes)/MiB)
	}
	return fmt.Sprintf("%.2f GiB", float32(bytes)/GiB)
}

type OptionGo struct {
	Password string
	MuxConfig
}
