package outbound

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
)

type ExperimentalOptions struct {
	HostResolverRules *hostResolverRules `json:"HostResolverRules,omitempty"`
	SSLKeyLogFile     string             `json:"ssl_key_log_file,omitempty"`
	FeatureList       string             `json:"feature_list,omitempty"`
}

type hostResolverRules struct {
	HostResolverRules string `json:"host_resolver_rules,omitempty"`
}

type CronetOption struct {
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	Network           string            `proxy:"network,omitempty"`
	User              string            `proxy:"user"`
	PassWord          string            `proxy:"password"`
	HostResolverRules string            `proxy:"host-resolver-rules,omitempty"`
	FeatureList       string            `proxy:"feature_list,omitempty"`
	Headers           map[string]string `proxy:"headers,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	ServerName        string            `proxy:"servername,omitempty"`
	NetLog            string            `proxy:"log-net-log"` //TODO
}

func (c *CronetOption) ExperimentalOptions() *ExperimentalOptions {
	return &ExperimentalOptions{
		HostResolverRules: &hostResolverRules{HostResolverRules: c.HostResolverRules},
		FeatureList:       c.FeatureList,
	}
}

type Cronet struct {
	*Base
	engine        cronet.Engine
	option        *CronetOption
	authorization string
	url           string
}

// SupportUDP implements C.ProxyAdapter
func (c *Cronet) SupportUDP() bool {
	return false
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (c *Cronet) ListenPacketOnStreamConn(con net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	//TODO implement me
	panic("implement me")
}

// StreamConn implements C.ProxyAdapter
func (c *Cronet) StreamConn(con net.Conn, metadata *C.Metadata) (net.Conn, error) {
	headers := map[string]string{
		"-connect-authority":  fmt.Sprintf("%s:%s", metadata.DstIP.String(), metadata.DstPort),
		"Padding":             generatePaddingHeader(),
		"proxy-authorization": c.authorization,
	}
	for key, value := range c.option.Headers {
		headers[key] = value
	}
	bidiConn := c.engine.StreamEngine().CreateConn(true, false)
	err := bidiConn.Start("CONNECT", c.url, headers, 0, false)
	if err != nil {
		return nil, E.Cause(err, "start bidi conn")
	}
	return &PaddingConn{Conn: bidiConn}, nil
}

func (c *Cronet) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	con, err := dialer.DialContext(ctx, "tcp", c.addr, c.Base.DialOptions(opts...)...)
	defer safeConnClose(con, err)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}
	tcpKeepAlive(con)
	con, err = c.StreamConn(con, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(con, c), err
}

func NewCronet(option CronetOption) (*Cronet, error) {
	engine := cronet.NewEngine()
	fmt.Println("libcronet " + engine.Version())
	runtime.SetFinalizer(&engine, func(engine *cronet.Engine) {
		engine.Shutdown()
		engine.Destroy()
	})
	params := cronet.NewEngineParams()
	experimentalOptionsJSON, err := json.Marshal(option.ExperimentalOptions())
	if err != nil {
		log.Fatalln(err.Error())
	}
	params.SetExperimentalOptions(string(experimentalOptionsJSON))
	url := "%s://%s:%s@%s:%s"
	switch option.Network {
	case "https", "http":
		params.SetEnableHTTP2(true)
		params.SetEnableQuic(false)
		url = fmt.Sprintf(url, "https", option.User, option.PassWord, option.ServerName, option.Port)
	case "quic":
		params.SetEnableHTTP2(false)
		params.SetEnableQuic(true)
		url = fmt.Sprintf(url, "quic", option.User, option.PassWord, option.ServerName, option.Port)
	default:
		log.Fatalln("unknown proxy scheme: %s", option.Network)
	}

	engine.StartWithParams(params)
	params.Destroy()

	if option.NetLog != "" {
		engine.StartNetLogToFile(option.NetLog, true)
	}

	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(option.User+":"+option.PassWord))
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	return &Cronet{
		Base: &Base{
			name: option.Name,
			addr: addr,
			tp:   C.Cronet,
			udp:  false,
		},
		option:        &option,
		authorization: authorization,
		url:           url,
		engine:        engine,
	}, nil

}

func generatePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		// Codes that won't be Huffman coded.
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

const kFirstPaddings = 8

type PaddingConn struct {
	net.Conn

	rAddr            net.Addr
	readPadding      int
	writePadding     int
	readRemaining    int
	paddingRemaining int
}

func (c *PaddingConn) Read(p []byte) (n int, err error) {
	if c.readRemaining > 0 {
		if len(p) > c.readRemaining {
			p = p[:c.readRemaining]
		}
		n, err = c.Read(p)
		if err != nil {
			return
		}
		c.readRemaining -= n
		return
	}
	if c.paddingRemaining > 0 {
		err = rw.SkipN(c.Conn, c.paddingRemaining)
		if err != nil {
			return
		}
		c.readRemaining = 0
	}
	if c.readPadding < kFirstPaddings {
		paddingHdr := p[:3]
		_, err = io.ReadFull(c.Conn, paddingHdr)
		if err != nil {
			return
		}
		originalDataSize := int(binary.BigEndian.Uint16(paddingHdr[:2]))
		paddingSize := int(paddingHdr[2])
		if len(p) > originalDataSize {
			p = p[:originalDataSize]
		}
		n, err = c.Conn.Read(p)
		if err != nil {
			return
		}
		c.readPadding++
		c.readRemaining = originalDataSize - n
		c.paddingRemaining = paddingSize
		return
	}
	return c.Conn.Read(p)
}

func (c *PaddingConn) Write(p []byte) (n int, err error) {
	if c.writePadding < kFirstPaddings {
		paddingSize := rand.Intn(256)
		_buffer := buf.Make(3 + len(p) + paddingSize)
		defer runtime.KeepAlive(_buffer)
		buffer := common.Dup(_buffer)
		binary.BigEndian.PutUint16(buffer, uint16(len(p)))
		buffer[2] = byte(paddingSize)
		copy(buffer[3:], p)
		_, err = c.Conn.Write(buffer)
		if err != nil {
			return
		}
		c.writePadding++
	}
	return c.Conn.Write(p)
}

func (c *PaddingConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writePadding < kFirstPaddings {
		bufferLen := buffer.Len()
		paddingSize := rand.Intn(256)
		header := buffer.ExtendHeader(3)
		binary.BigEndian.PutUint16(header, uint16(bufferLen))
		header[2] = byte(paddingSize)
		buffer.Extend(paddingSize)
		c.writePadding++
	}
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

func (c *PaddingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}

func (c *PaddingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.rAddr, err
}
