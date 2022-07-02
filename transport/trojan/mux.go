package trojan

import (
	"context"
	"errors"
	"github.com/Dreamacro/clash/log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/xtaci/smux"
)

type DialFunc func(ctx context.Context, config *MuxConfig) (net.Conn, error)

type muxID uint32

func generateMuxID() muxID {
	return muxID(rand.Uint32())
}

type smuxClientInfo struct {
	id             muxID
	client         *smux.Session
	lastActiveTime time.Time
	underlayConn   net.Conn //muxConn
}

type MuxTransport struct {
	clientPoolLock sync.Mutex
	clientPool     map[muxID]*smuxClientInfo //tls 连接数
	dialFunc       DialFunc
	option         *OptionGo
	concurrency    int
	timeout        time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *MuxTransport) Close() error {
	c.cancel()
	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()
	for _, info := range c.clientPool {
		info.client.Close()
	}
	return nil
}

func (c *MuxTransport) cleanLoop() {
	var checkDuration time.Duration
	if c.timeout <= 0 {
		checkDuration = time.Second * 10
	} else {
		checkDuration = c.timeout / 4
	}
	for {
		select {
		case <-time.After(checkDuration):
			c.clientPoolLock.Lock()
			for id, info := range c.clientPool {
				if info.client.IsClosed() {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
				} else if info.client.NumStreams() == 0 && time.Since(info.lastActiveTime) > c.timeout {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
				}
			}
			log.Infoln("cleanLoop: tcp connection number: %d", len(c.clientPool))
			c.clientPoolLock.Unlock()
		case <-c.ctx.Done():
			c.clientPoolLock.Lock()
			for id, info := range c.clientPool {
				info.client.Close()
				info.underlayConn.Close()
				delete(c.clientPool, id)
			}
			c.clientPoolLock.Unlock()
			return
		}
	}
}

func (c *MuxTransport) newMuxClient(metadata *C.Metadata) (*smuxClientInfo, error) {
	// The mutex should be locked when this function is called
	id := generateMuxID()
	if _, found := c.clientPool[id]; found {
		return nil, errors.New("duplicated id")
	}
	conn, err := c.dialFunc(c.ctx, &c.option.MuxConfig)
	if err != nil {
		return nil, err
	}
	//addr, err := NewAddressFromAddr("tcp", metadata.DstIP.String()+":"+metadata.DstPort)
	//if err != nil {
	//	return nil, err
	//}
	outcon := &OutboundConn{
		hexPassword:       hexSha224([]byte(c.option.Password)),
		headerWrittenOnce: sync.Once{},
		Conn:              conn,
		metadata: &Metadata{
			Command: CommandMux,
			Address: &Address{
				DomainName:  "MUX_CONN",
				AddressType: DomainName,
			},
		},
	}

	muxCon := newMuxConn(outcon)
	smuxConfig := smux.DefaultConfig()
	// smuxConfig.KeepAliveDisabled = true
	client, err := smux.Client(muxCon, smuxConfig)
	if err != nil {
		return nil, err
	}
	info := &smuxClientInfo{
		client:         client,
		underlayConn:   muxCon,
		id:             id,
		lastActiveTime: time.Now(),
	}
	c.clientPool[id] = info
	return info, nil
}

func (c *MuxTransport) DialConn(metadata *C.Metadata, opts ...dialer.Option) (net.Conn, error) {
	createNewConn := func(info *smuxClientInfo) (*simplesocks, error) {
		rwc, err := info.client.Open()
		info.lastActiveTime = time.Now()
		if err != nil {
			info.underlayConn.Close()
			info.client.Close()
			delete(c.clientPool, info.id)
			return nil, err
		}
		streamCon := &streamMuxConn{
			rwc:  rwc,
			Conn: info.underlayConn,
		}

		addr, err := NewAddressFromAddr("tcp", metadata.DstIP.String()+":"+metadata.DstPort)
		if err != nil {
			return nil, err
		}
		return &simplesocks{
			Conn: streamCon,
			metadata: &Metadata{
				Command: CommandTCP,
				Address: addr,
			},
		}, nil
	}

	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()
	for _, info := range c.clientPool {
		if info.client.IsClosed() {
			delete(c.clientPool, info.id)
			continue
		}
		if info.client.NumStreams() < c.concurrency || c.concurrency <= 0 {
			return createNewConn(info)
		}
	}
	info, err := c.newMuxClient(metadata)
	if err != nil {
		return nil, err
	}
	log.Infoln("DialConn: tcp connection number: %d", len(c.clientPool))
	return createNewConn(info)
}

func NewMuxTransport(ctx context.Context, dialFunc DialFunc, option *OptionGo) (*MuxTransport, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &MuxTransport{
		dialFunc:    dialFunc,
		option:      option,
		concurrency: option.Concurrency,
		timeout:     time.Duration(option.IdleTimeout) * time.Second,
		ctx:         ctx,
		cancel:      cancel,
		clientPool:  make(map[muxID]*smuxClientInfo),
	}
	go client.cleanLoop()
	return client, nil
}
