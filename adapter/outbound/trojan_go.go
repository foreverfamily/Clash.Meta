package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/trojan"
)

type TrojanGO struct {
	*Base
	instance *trojan.Trojan
	option   *TrojanOption

	//for trojan-go mux
	muxTransport *trojan.MuxTransport
	optionGo     *TrojanGoOption
}

type TrojanGoOption struct {
	BasicOption
	Name           string           `proxy:"name"`
	Server         string           `proxy:"server"`
	Port           int              `proxy:"port"`
	Password       string           `proxy:"password"`
	ALPN           []string         `proxy:"alpn,omitempty"`
	SNI            string           `proxy:"sni,omitempty"`
	SkipCertVerify bool             `proxy:"skip-cert-verify,omitempty"`
	UDP            bool             `proxy:"udp,omitempty"`
	Network        string           `proxy:"network,omitempty"`
	MuxOpts        trojan.MuxConfig `proxy:"mux-opts,omitempty"`
	WSOpts         WSOptions        `proxy:"ws-opts,omitempty"`
}

func (t *TrojanGO) plainStream(c net.Conn) (net.Conn, error) {
	if t.option.Network == "ws" {
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &trojan.WebsocketOption{
			Host: host,
			Port: port,
			Path: t.option.WSOpts.Path,
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range t.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		return t.instance.StreamWebsocketConn(c, wsOpts)
	}

	return t.instance.StreamConn(c)
}

// StreamConn implements C.ProxyAdapter
func (t *TrojanGO) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	//TODO
	var err error
	c, err = t.plainStream(c)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	if metadata.NetWork == C.UDP {
		err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
		return c, err
	}
	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

// DialContext implements C.ProxyAdapter
func (t *TrojanGO) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	if t.optionGo.MuxOpts.Enabled {
		c, err := t.muxTransport.DialConn(metadata, opts...)
		if err != nil {
			return nil, err
		}
		return NewConn(c, t), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = t.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *TrojanGO) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn
	c, err = dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer safeConnClose(c, err)
	tcpKeepAlive(c)
	c, err = t.plainStream(c)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// ListenPacketOnStreamConn implements C.ProxyAdapter relay
func (t *TrojanGO) ListenPacketOnStreamConn(c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// SupportUOT implements C.ProxyAdapter
func (t *TrojanGO) SupportUOT() bool {
	return true
}

func NewTrojanGO(optionGo TrojanGoOption) (*TrojanGO, error) {
	addr := net.JoinHostPort(optionGo.Server, strconv.Itoa(optionGo.Port))
	tOption := &trojan.Option{
		Password:       optionGo.Password,
		ALPN:           optionGo.ALPN,
		ServerName:     optionGo.Server,
		SkipCertVerify: optionGo.SkipCertVerify,
	}

	option := TrojanOption{
		BasicOption:    optionGo.BasicOption,
		Name:           optionGo.Name,
		Server:         optionGo.Server,
		Port:           optionGo.Port,
		Password:       optionGo.Password,
		ALPN:           optionGo.ALPN,
		SNI:            optionGo.SNI,
		SkipCertVerify: optionGo.SkipCertVerify,
		UDP:            optionGo.UDP,
		Network:        optionGo.Network,
		WSOpts:         optionGo.WSOpts,
	}

	toption := &trojan.OptionGo{
		Password:  optionGo.Password,
		MuxConfig: optionGo.MuxOpts,
	}

	if optionGo.SNI != "" {
		tOption.ServerName = optionGo.SNI
	}

	t := &TrojanGO{
		Base: &Base{
			name:  optionGo.Name,
			addr:  addr,
			tp:    C.TrojanGo,
			udp:   optionGo.UDP,
			iface: optionGo.Interface,
			rmark: optionGo.RoutingMark,
		},
		instance: trojan.New(tOption),
		option:   &option,
		optionGo: &optionGo,
	}

	if optionGo.MuxOpts.Enabled {
		dialFn := func(ctx context.Context, config *trojan.MuxConfig) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
			}
			tcpKeepAlive(c)
			defer safeConnClose(c, err)

			c, err = t.plainStream(c)
			if err != nil {
				return nil, err
			}
			return c, err
		}
		mux, err := trojan.NewMuxTransport(context.Background(), dialFn, toption)
		if err != nil {
			return nil, err
		}
		t.muxTransport = mux
	}

	return t, nil
}
