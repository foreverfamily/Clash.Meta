package trojan

import (
	"bytes"
	"net"
)

// simplesocks is a simplesocks connection
type simplesocks struct {
	net.Conn      //streamMuxConn
	metadata      *Metadata
	headerWritten bool
}

func (c *simplesocks) Metadata() *Metadata {
	return c.metadata
}

func (c *simplesocks) Write(payload []byte) (int, error) {
	if !c.headerWritten {
		buf := bytes.NewBuffer(make([]byte, 0, 4096))
		err := c.metadata.WriteTo(buf)
		if err != nil {
			return 0, err
		}
		buf.Write(payload)
		_, err = c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, err
		}
		c.headerWritten = true
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}
