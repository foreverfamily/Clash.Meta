package outbound

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/sanity-io/litter"
	"io"
	"math/rand"
	"net"
	"net/url"
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
	streamEngine  cronet.StreamEngine
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

//error	http.log.error	lookup of invalid IP failed: lookup invalid IP: no such host
//{"request": {"remote_ip": "183.134.99.132", "remote_port": "60198", "proto": "HTTP/2.0", "method": "CONNECT", "host": "invalid IP:80", "uri": "invalid IP:80",
//"headers": {
//"Proxy-Authorization": [],
//"User-Agent": [""], "Padding": ["[^]]?<!<>><`+@#}~~~~~~~~~~~~~~~"]},
//"tls": {"resumed": false, "version": 772, "cipher_suite": 4865, "proto": "h2", "server_name": "hk.lovechildrens.xyz"}},
//"duration": 0.001539812, "status": 502, "err_id": "9qa9ptcd6", "err_trace": "forwardproxy.Handler.dialContextCheckACL (forwardproxy.go:495)"}

// StreamConn implements C.ProxyAdapter
func (c *Cronet) StreamConn(con net.Conn, metadata *C.Metadata) (net.Conn, error) {
	headers := map[string]string{
		"-connect-authority":  metadata.RemoteAddress(),
		"Padding":             generatePaddingHeader(),
		"Proxy-Authorization": c.authorization,
	}
	for key, value := range c.option.Headers {
		headers[key] = value
	}
	log.Debugln("StreamConn: url = %s", litter.Sdump(headers))
	bidiConn := c.streamEngine.CreateConn(true, false)
	err := bidiConn.Start("CONNECT", c.url, headers, 0, false)
	if err != nil {
		return nil, E.Cause(err, "start bidi conn")
	}
	return &PaddingConn{Conn: bidiConn}, nil
}

func (c *Cronet) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	con, err := c.StreamConn(nil, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(con, c), err
}

func NewCronet(option CronetOption) (*Cronet, error) {
	engine := cronet.NewEngine()
	fmt.Println("libcronet " + engine.Version())
	params := cronet.NewEngineParams()
	//experimentalOptionsJSON, err := json.Marshal(option.ExperimentalOptions())
	//if err != nil {
	//	log.Fatalln(err.Error())
	//}
	//params.SetExperimentalOptions(string(experimentalOptionsJSON))
	//params.ExperimentalOptions()
	urlStr := "%s://%s:%s@%s:%d"
	switch option.Network {
	case "https", "http":
		params.SetEnableHTTP2(true)
		params.SetEnableQuic(false)
		urlStr = fmt.Sprintf(urlStr, "https", option.User, option.PassWord, option.ServerName, option.Port)
	case "quic":
		params.SetEnableHTTP2(false)
		params.SetEnableQuic(true)
		urlStr = fmt.Sprintf(urlStr, "quic", option.User, option.PassWord, option.ServerName, option.Port)
	default:
		log.Fatalln("unknown proxy scheme: %s", option.Network)
	}
	log.Debugln("NewCronet: url = %s", urlStr)
	proxyURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	var proxyAuthorization string
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		proxyAuthorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+password))
		proxyURL.User = nil
	}
	log.Debugln("NewCronet: proxyURL = %s, proxyAuthorization = %s", litter.Sdump(proxyURL), proxyAuthorization)
	engine.StartWithParams(params)
	params.Destroy()

	if option.NetLog != "" {
		engine.StartNetLogToFile(option.NetLog, true)
	}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	return &Cronet{
		Base: &Base{
			name: option.Name,
			addr: addr,
			tp:   C.Cronet,
			udp:  false,
		},
		option:        &option,
		authorization: proxyAuthorization,
		url:           proxyURL.String(),
		engine:        engine,
		streamEngine:  engine.StreamEngine(),
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
