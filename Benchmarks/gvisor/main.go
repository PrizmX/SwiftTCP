// Comparable userspace-stack bench against SwiftTCP (same scenarios / JSON).
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID tcpip.NICID = 1

var (
	clientIP   = [4]byte{10, 0, 0, 1}
	serverIP   = [4]byte{10, 0, 0, 2}
	clientIP6  = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	serverIP6  = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	stackLabel = "gvisor"
)

type result struct {
	Stack                string  `json:"stack"`
	Scenario             string  `json:"scenario"`
	DurationS            float64 `json:"durationS"`
	WarmupS              float64 `json:"warmupS"`
	Connections          int     `json:"connections"`
	PayloadBytes         int     `json:"payloadBytes"`
	Batch                int     `json:"batch"`
	Loops                int     `json:"loops"`
	WindowBytes          int     `json:"windowBytes"`
	PacketsIn            uint64  `json:"packetsIn"`
	BytesIn              uint64  `json:"bytesIn"`
	PacketsOut           uint64  `json:"packetsOut"`
	BytesOut             uint64  `json:"bytesOut"`
	DeliveredBytes       uint64  `json:"deliveredBytes"`
	Established          uint64  `json:"established"`
	PPS                  float64 `json:"pps"`
	Gbps                 float64 `json:"gbps"`
	AppGbps              float64 `json:"appGbps"`
	CPUUserS             float64 `json:"cpuUserS"`
	CPUSysS              float64 `json:"cpuSysS"`
	CPUCores             float64 `json:"cpuCores"`
	RSSBeforeBytes       uint64  `json:"rssBeforeBytes"`
	RSSAfterBytes        uint64  `json:"rssAfterBytes"`
	RSSDeltaBytes        uint64  `json:"rssDeltaBytes"`
	FootprintBeforeBytes uint64  `json:"footprintBeforeBytes"`
	FootprintAfterBytes  uint64  `json:"footprintAfterBytes"`
	BytesPerConnection   float64 `json:"bytesPerConnection"`
	RPS                  float64 `json:"rps"`
	IngestP50Us          float64 `json:"ingestP50Us"`
	IngestP99Us          float64 `json:"ingestP99Us"`
	HandshakeP50Us       float64 `json:"handshakeP50Us"`
	HandshakeP99Us       float64 `json:"handshakeP99Us"`
	FirstByteP50Us       float64 `json:"firstByteP50Us"`
	FirstByteP99Us       float64 `json:"firstByteP99Us"`
	LossPct              float64 `json:"lossPct"`
	Notes                string  `json:"notes"`
}

func main() {
	scenario := flag.String("scenario", "tcp-rx", "scenario name")
	durationSec := flag.Float64("duration", 5, "timed window seconds")
	warmupSec := flag.Float64("warmup", 1, "warmup seconds")
	connections := flag.Int("connections", 8, "parallel flows")
	payload := flag.Int("payload", 1460, "TCP payload bytes")
	batch := flag.Int("batch", 64, "packets per inject burst")
	window := flag.Int("window", 64*1024, "receive window")
	hold := flag.Int("hold-conns", 4096, "tcp-hold connections")
	active := flag.Int("active-conns", 256, "tcp-active connections")
	rpsBytes := flag.Int("rps-bytes", 8192, "tcp-rps payload per connection")
	loss := flag.Float64("loss", 2, "tcp-loss drop percent")
	loops := flag.Int("loops", runtime.NumCPU(), "GOMAXPROCS / reported loop count")
	stackName := flag.String("stack", "gvisor", "JSON stack field")
	jsonOut := flag.Bool("json", false, "JSON array to stdout")
	output := flag.String("output", "", "write JSON file")
	flag.Parse()

	runtime.GOMAXPROCS(*loops)
	stackLabel = *stackName

	duration := time.Duration(*durationSec * float64(time.Second))
	warmup := time.Duration(*warmupSec * float64(time.Second))

	pl := *payload
	name := *scenario
	if name == "tcp-rx-small" {
		pl = 64
	}
	if name == "tcp-rx6" && pl > 1440 {
		pl = 1440
	}

	var res result
	switch *scenario {
	case "tcp-rx", "tcp-rx-small":
		res = runTCPRx(name, duration, warmup, *connections, pl, *batch, *window, *loops, false, 0, true, false)
	case "tcp-tx":
		res = runTCPTx(duration, warmup, *connections, pl, *batch, *window)
	case "tcp-duplex":
		res = runTCPDuplex(duration, warmup, *connections, pl, *batch, *window)
	case "tcp-active":
		res = runTCPRx("tcp-active", duration, warmup, *active, pl, *batch, *window, *loops, false, 0, true, false)
		res.Notes = fmt.Sprintf("%d live flows transferring; RSS Δ is under traffic not idle hold", *active)
		res.Connections = *active
	case "tcp-rps":
		res = runTCPRps(duration, warmup, *rpsBytes, pl, *window)
	case "tcp-latency":
		res = runTCPLatency(duration, *connections, pl, *batch, *window)
	case "tcp-loss":
		res = runTCPRx("tcp-loss", duration, warmup, *connections, pl, *batch, *window, *loops, false, *loss, true, true)
	case "tcp-rx6":
		res = runTCPRx("tcp-rx6", duration, warmup, *connections, pl, *batch, *window, *loops, true, 0, true, false)
	case "tcp-scale":
		res = runTCPRx("tcp-scale", duration, warmup, *connections, pl, *batch, *window, *loops, false, 0, true, false)
		res.Notes = fmt.Sprintf("RX bulk at GOMAXPROCS=%d", *loops)
	case "tcp-cps":
		res = runTCPCps(duration, warmup, *batch, *window)
	case "tcp-hold":
		res = runTCPHold(*hold, *window)
	case "icmp-echo":
		res = runICMP(duration, warmup, *batch, pl)
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %s\n", *scenario)
		os.Exit(2)
	}
	res.WarmupS = warmup.Seconds()
	res.WindowBytes = *window
	res.PayloadBytes = pl
	res.Batch = *batch
	res.Loops = *loops
	res.Stack = *stackName
	if *scenario == "tcp-hold" {
		res.Connections = *hold
	} else if *scenario != "tcp-active" {
		res.Connections = *connections
	}

	data, err := json.MarshalIndent([]result{res}, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			panic(err)
		}
	}
	if *jsonOut || *output == "" {
		_, _ = os.Stdout.Write(data)
	}
}

type env struct {
	stack         *stack.Stack
	nic           *channel.Endpoint
	txPackets     atomic.Uint64
	txBytes       atomic.Uint64
	txDataPackets atomic.Uint64
	txDataBytes   atomic.Uint64
	delivered     atomic.Uint64
	accepts       atomic.Uint64
	completed     atomic.Uint64
	autoAck       atomic.Bool
	autoDrain     bool
	ackCh         chan []byte
	synCh         chan []byte
	conns         chan *gonet.TCPConn
	seqs          sync.Map // client port → sequence
	cancel        context.CancelFunc
}

func newEnv(window int, accept bool, autoDrain bool) *env {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	nic := channel.New(32768, 1500, "")
	nic.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	if err := s.CreateNIC(nicID, nic); err != nil {
		panic(err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(serverIP),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		panic(err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(serverIP6),
			PrefixLen: 64,
		},
	}, stack.AddressProperties{}); err != nil {
		panic(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	_ = s.SetPromiscuousMode(nicID, true)
	tw := tcpip.TCPTimeWaitTimeoutOption(50 * time.Millisecond)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &tw)

	ctx, cancel := context.WithCancel(context.Background())
	e := &env{
		stack:     s,
		nic:       nic,
		autoDrain: autoDrain,
		ackCh:     make(chan []byte, 32768),
		synCh:     make(chan []byte, 64),
		conns:     make(chan *gonet.TCPConn, 16*1024),
		cancel:    cancel,
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ack := <-e.ackCh:
				e.inject(ack)
			}
		}
	}()

	go func() {
		for {
			pkt := nic.ReadContext(ctx)
			if pkt == nil {
				return
			}
			raw := clonePkt(pkt)
			e.txPackets.Add(1)
			e.txBytes.Add(uint64(len(raw)))
			pkt.DecRef()
			p, ok := parseOutgoing(raw)
			if !ok {
				continue
			}
			if p.flags&header.TCPFlagSyn != 0 && p.flags&header.TCPFlagAck != 0 {
				select {
				case e.synCh <- p.ip:
				default:
				}
			}
			if p.payload > 0 {
				hdr := 40
				if p.v6 {
					hdr = 60
				}
				e.txDataPackets.Add(1)
				e.txDataBytes.Add(uint64(hdr + p.payload))
			}
			if e.autoAck.Load() && p.payload > 0 {
				seq := e.getSeq(p.dstPort)
				ack := p.seq + uint32(p.payload)
				var pkt []byte
				if p.v6 {
					pkt = ipv6TCP(p.dstPort, 80, seq, ack, header.TCPFlagAck, nil, 65535, nil)
				} else {
					pkt = ipv4TCP(p.dstPort, 80, seq, ack, header.TCPFlagAck, nil, 65535, nil)
				}
				select {
				case e.ackCh <- pkt:
				default:
				}
			}
		}
	}()

	if accept {
		fwd := tcp.NewForwarder(s, window, 16*1024, func(r *tcp.ForwarderRequest) {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				r.Complete(true)
				return
			}
			r.Complete(false)
			e.accepts.Add(1)
			conn := gonet.NewTCPConn(&wq, ep)
			select {
			case e.conns <- conn:
			default:
				_ = conn.Close()
				return
			}
			if autoDrain {
				go drainConn(conn, &e.delivered, &e.completed)
			}
		})
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	}
	return e
}

func (e *env) setSeq(port uint16, seq uint32) { e.seqs.Store(port, seq) }

func (e *env) getSeq(port uint16) uint32 {
	if v, ok := e.seqs.Load(port); ok {
		return v.(uint32)
	}
	return 1
}

func drainConn(conn *gonet.TCPConn, delivered, completed *atomic.Uint64) {
	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			delivered.Add(uint64(n))
		}
		if err != nil {
			_ = conn.Close()
			completed.Add(1)
			return
		}
	}
}

func (e *env) inject(pkt []byte) {
	proto := header.IPv4ProtocolNumber
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		proto = header.IPv6ProtocolNumber
	}
	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
	e.nic.InjectInbound(proto, buf)
	buf.DecRef()
}

func (e *env) close() {
	e.cancel()
	e.stack.Close()
}

func clonePkt(pkt *stack.PacketBuffer) []byte {
	out := make([]byte, 0, pkt.Size())
	for _, s := range pkt.AsSlices() {
		out = append(out, s...)
	}
	return out
}

type peer struct {
	port      uint16
	clientSeq uint32
	iss       uint32
	v6        bool
}

type parsedTCP struct {
	ip      []byte
	srcPort uint16
	dstPort uint16
	seq     uint32
	flags   header.TCPFlags
	payload int
	v6      bool
}

func parseOutgoing(raw []byte) (parsedTCP, bool) {
	off := 0
	if len(raw) >= 34 && raw[12] == 0x08 && raw[13] == 0x00 {
		off = 14
	} else if len(raw) >= 54 && raw[12] == 0x86 && raw[13] == 0xdd {
		off = 14
	}
	ip := raw[off:]
	if len(ip) < 40 {
		return parsedTCP{}, false
	}
	ver := ip[0] >> 4
	var tcpOff, tcpLen int
	v6 := false
	if ver == 4 {
		tcpOff = int(ip[0]&0x0f) * 4
		if tcpOff < 20 || len(ip) < tcpOff+20 {
			return parsedTCP{}, false
		}
		tcpLen = int(binary.BigEndian.Uint16(ip[2:4])) - tcpOff
	} else if ver == 6 {
		if ip[6] != 6 {
			return parsedTCP{}, false
		}
		tcpOff = 40
		tcpLen = int(binary.BigEndian.Uint16(ip[4:6]))
		v6 = true
	} else {
		return parsedTCP{}, false
	}
	if len(ip) < tcpOff+20 {
		return parsedTCP{}, false
	}
	tcp := ip[tcpOff:]
	dataOff := int(tcp[12]>>4) * 4
	payload := tcpLen - dataOff
	if payload < 0 {
		payload = 0
	}
	return parsedTCP{
		ip:      ip,
		srcPort: binary.BigEndian.Uint16(tcp[0:2]),
		dstPort: binary.BigEndian.Uint16(tcp[2:4]),
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		flags:   header.TCPFlags(tcp[13]),
		payload: payload,
		v6:      v6,
	}, true
}

func handshake(e *env, port uint16, iss uint32, v6 bool) (peer, error) {
	for len(e.synCh) > 0 {
		<-e.synCh
	}
	if v6 {
		e.inject(ipv6TCP(port, 80, iss, 0, header.TCPFlagSyn, nil, 65535, synOpts()))
	} else {
		e.inject(ipv4TCP(port, 80, iss, 0, header.TCPFlagSyn, nil, 65535, synOpts()))
	}
	select {
	case synAck := <-e.synCh:
		p, ok := parseOutgoing(synAck)
		if !ok {
			return peer{}, fmt.Errorf("bad SYN-ACK port %d", port)
		}
		clientSeq := iss + 1
		e.setSeq(port, clientSeq)
		if v6 {
			e.inject(ipv6TCP(port, 80, clientSeq, p.seq+1, header.TCPFlagAck, nil, 65535, nil))
		} else {
			e.inject(ipv4TCP(port, 80, clientSeq, p.seq+1, header.TCPFlagAck, nil, 65535, nil))
		}
		return peer{port: port, clientSeq: clientSeq, iss: p.seq, v6: v6}, nil
	case <-time.After(2 * time.Second):
		return peer{}, fmt.Errorf("timeout waiting SYN-ACK port %d", port)
	}
}

func makeTCP(p peer, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	if p.v6 {
		return ipv6TCP(p.port, 80, seq, ack, flags, payload, 65535, nil)
	}
	return ipv4TCP(p.port, 80, seq, ack, flags, payload, 65535, nil)
}

type splitMix64 struct{ state uint64 }

func (s *splitMix64) next() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func waitDelivered(e *env, want uint64, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for e.delivered.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
}

func takeConn(e *env) *gonet.TCPConn {
	select {
	case c := <-e.conns:
		return c
	case <-time.After(2 * time.Second):
		panic("accept timeout")
	}
}

func runTCPRx(name string, dur, warmup time.Duration, conns, payload, batch, window, workers int, v6 bool, lossPct float64, sample, reorder bool) result {
	if v6 && payload > 1440 {
		payload = 1440
	}
	e := newEnv(window, true, true)
	defer e.close()
	peers := make([]peer, conns)
	for i := 0; i < conns; i++ {
		p, err := handshake(e, uint16(10000+i), 1000, v6)
		if err != nil {
			panic(err)
		}
		peers[i] = p
		_ = takeConn(e)
	}
	chunk := bytesOf('a', payload)
	rng := splitMix64{state: 0xC0FFEE42}
	delayed := make([][]byte, 0, batch)
	ingest := make([]float64, 0, 4096)
	nbatch := 0
	hdr := 40
	if v6 {
		hdr = 60
	}
	inject := func() {
		pkts := make([][]byte, 0, batch+len(delayed))
		pkts = append(pkts, delayed...)
		delayed = delayed[:0]
		for i := 0; i < batch; i++ {
			idx := i % conns
			pkt := makeTCP(peers[idx], peers[idx].clientSeq, peers[idx].iss+1, header.TCPFlagAck|header.TCPFlagPsh, chunk)
			peers[idx].clientSeq += uint32(payload)
			if lossPct > 0 {
				roll := float64(rng.next()%10_000) / 100.0
				if roll < lossPct {
					delayed = append(delayed, pkt)
					continue
				}
			}
			pkts = append(pkts, pkt)
		}
		nbatch++
		if reorder && nbatch%5 == 0 && len(pkts) >= 2 {
			for i, j := 0, len(pkts)-1; i < j; i, j = i+1, j-1 {
				pkts[i], pkts[j] = pkts[j], pkts[i]
			}
		}
		start := e.delivered.Load()
		want := start + uint64(len(pkts)*payload)
		t0 := time.Now()
		// Serial inject: concurrent InjectInbound contends on netstack locks and
		// *lowers* pps (see tcp-scale 1p vs 8p). GOMAXPROCS still applies to drain.
		_ = workers
		for _, pkt := range pkts {
			e.inject(pkt)
		}
		// Loss/reorder leaves in-order holes, so delivered lags injected on purpose.
		// Waiting for full want would hit the 100ms cap every batch (~600 pps).
		if lossPct == 0 && !reorder {
			waitDelivered(e, want, 100*time.Millisecond)
		} else {
			runtime.Gosched()
		}
		if sample && len(ingest) < 8192 {
			ingest = append(ingest, float64(time.Since(t0).Microseconds()))
		}
	}
	until(warmup, inject)
	e.delivered.Store(0)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	e.txDataPackets.Store(0)
	e.txDataBytes.Store(0)
	ingest = ingest[:0]
	res := measure(name, dur, inject, e, uint64(conns), "RX bulk via gVisor netstack Forwarder", payload)
	if v6 {
		res.Notes = "IPv6 RX bulk; L3 includes 60B IPv6+TCP header per segment"
		if payload > 0 {
			segs := res.DeliveredBytes / uint64(payload)
			res.BytesIn = segs * uint64(hdr+payload)
			res.Gbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
		}
	}
	if lossPct > 0 {
		res.LossPct = lossPct
		res.Notes = fmt.Sprintf("RX with %.1f%% drop (retransmit next batch) + reverse every 5th batch", lossPct)
	}
	p50, p99 := percentilePair(ingest)
	res.IngestP50Us, res.IngestP99Us = p50, p99
	return res
}

func runTCPTx(dur, warmup time.Duration, conns, payload, batch, window int) result {
	e := newEnv(window, true, true)
	defer e.close()
	e.autoAck.Store(true)
	writers := make([]*gonet.TCPConn, 0, conns)
	for i := 0; i < conns; i++ {
		if _, err := handshake(e, uint16(20000+i), 1000, false); err != nil {
			panic(err)
		}
		writers = append(writers, takeConn(e))
	}
	chunk := bytesOf('b', payload)
	pump := func() {
		for i := 0; i < batch; i++ {
			c := writers[i%len(writers)]
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write(chunk)
		}
	}
	until(warmup, pump)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	e.txDataPackets.Store(0)
	e.txDataBytes.Store(0)
	res := measure("tcp-tx", dur, pump, e, uint64(conns), "TX: Write(batch segments) + auto ACK; pps counts payload packets", payload)
	res.PacketsIn = e.txDataPackets.Load()
	res.BytesIn = e.txDataBytes.Load()
	if res.DurationS < 1e-9 {
		res.DurationS = 1e-9
	}
	res.PPS = float64(res.PacketsIn) / res.DurationS
	res.Gbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
	res.AppGbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
	return res
}

func runTCPCps(dur, warmup time.Duration, batch, window int) result {
	e := newEnv(window, true, true)
	defer e.close()
	port := uint32(30000)
	churn := func() {
		for i := 0; i < batch; i++ {
			p, err := handshake(e, uint16(port), 1000, false)
			port++
			if port > 60000 {
				port = 30000
			}
			if err != nil {
				continue
			}
			_ = takeConn(e)
			e.inject(ipv4TCP(p.port, 80, p.clientSeq, p.iss+1, header.TCPFlagRst|header.TCPFlagAck, nil, 0, nil))
		}
	}
	until(warmup, churn)
	e.accepts.Store(0)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	var n uint64
	wrapped := func() {
		churn()
		n += uint64(batch)
	}
	res := measure("tcp-cps", dur, wrapped, e, 0, "handshake + RST churn", 0)
	res.PacketsIn = n * 3
	res.BytesIn = n * 3 * 52
	res.Established = e.accepts.Load()
	res.PPS = float64(res.PacketsIn) / res.DurationS
	res.Gbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
	return res
}

func runTCPHold(n, window int) result {
	e := newEnv(window, true, false)
	defer e.close()
	rss0, heap0 := mem()
	cpu0 := cpu()
	t0 := time.Now()
	held := make([]*gonet.TCPConn, 0, n)
	for i := 0; i < n; i++ {
		if _, err := handshake(e, uint16(10000+i), 1000, false); err != nil {
			panic(err)
		}
		held = append(held, takeConn(e))
	}
	time.Sleep(200 * time.Millisecond)
	wall := time.Since(t0).Seconds()
	cpu1 := cpu()
	rss1, heap1 := mem()
	est := e.accepts.Load()
	runtime.KeepAlive(held)
	return finish("tcp-hold", wall, uint64(n*2), uint64(n*2*52), e.txPackets.Load(), e.txBytes.Load(), 0, est, cpu0, cpu1, rss0, rss1, heap0, heap1, "idle ESTABLISHED; RSS is current RSS delta (statm); footprint = Go heap")
}

func runICMP(dur, warmup time.Duration, batch, payload int) result {
	e := newEnv(64*1024, false, false)
	defer e.close()
	if payload < 8 {
		payload = 8
	}
	req := ipv4ICMPEcho(payload)
	inject := func() {
		for i := 0; i < batch; i++ {
			e.inject(req)
		}
		runtime.Gosched()
	}
	until(warmup, inject)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	var pkts uint64
	wrapped := func() {
		inject()
		pkts += uint64(batch)
	}
	res := measure("icmp-echo", dur, wrapped, e, 0, "ICMP echo request flood", payload)
	res.PacketsIn = pkts
	res.BytesIn = pkts * uint64(len(req))
	res.PPS = float64(res.PacketsIn) / res.DurationS
	res.Gbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
	return res
}

func measure(name string, dur time.Duration, fn func(), e *env, est uint64, notes string, payload int) result {
	rss0, heap0 := mem()
	cpu0 := cpu()
	t0 := time.Now()
	until(dur, fn)
	wall := time.Since(t0).Seconds()
	cpu1 := cpu()
	rss1, heap1 := mem()
	delivered := e.delivered.Load()
	var segs uint64
	if payload > 0 {
		segs = delivered / uint64(payload)
	}
	l3 := segs * uint64(40+payload)
	// tcp-tx and icmp-echo legitimately deliver nothing through the TCP read
	// path (TX direction has no inbound data; icmp is stateless and reports its
	// own injection counts), so only flag RX-delivery scenarios.
	if payload > 0 && delivered == 0 && name != "tcp-tx" && name != "icmp-echo" {
		// The TX-count fallback previously masqueraded failed RX measurements
		// (delivered==0) as real numbers. Report the failure explicitly instead:
		// zeroed pps/gbps plus a stderr warning, so run.sh surfaces it.
		fmt.Fprintf(os.Stderr, "WARN: %s deliveredBytes=0 (payload=%d): RX path delivered nothing; result is invalid\n", name, payload)
		notes = "INVALID: deliveredBytes=0 (RX path delivered nothing) — pps/gbps are 0"
	}
	return finish(name, wall, segs, l3, e.txPackets.Load(), e.txBytes.Load(), delivered, est, cpu0, cpu1, rss0, rss1, heap0, heap1, notes)
}

func synOpts() []byte {
	return []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7}
}

func ipv4TCP(sport, dport uint16, seq, ack uint32, flags header.TCPFlags, payload []byte, window uint16, opts []byte) []byte {
	if opts == nil {
		opts = []byte{}
	}
	for len(opts)%4 != 0 {
		opts = append(opts, 1)
	}
	tcpHdr := 20 + len(opts)
	total := 20 + tcpHdr + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[6:], 0x4000)
	b[8] = 64
	b[9] = 6
	copy(b[12:16], clientIP[:])
	copy(b[16:20], serverIP[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint32(b[24:], seq)
	binary.BigEndian.PutUint32(b[28:], ack)
	b[32] = byte((tcpHdr / 4) << 4)
	b[33] = uint8(flags)
	binary.BigEndian.PutUint16(b[34:], window)
	copy(b[40:], opts)
	copy(b[20+tcpHdr:], payload)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	binary.BigEndian.PutUint16(b[36:], tcpChecksum(b[20:], clientIP, serverIP))
	return b
}

func ipv4ICMPEcho(payload int) []byte {
	body := bytesOf('p', payload)
	total := 20 + 8 + len(body)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[6:], 0x4000)
	b[8] = 64
	b[9] = 1
	copy(b[12:16], clientIP[:])
	copy(b[16:20], serverIP[:])
	b[20] = 8
	copy(b[28:], body)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	binary.BigEndian.PutUint16(b[22:], checksum(b[20:]))
	return b
}

func checksum(p []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	if len(p)%2 == 1 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(tcp []byte, src, dst [4]byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += 6 + uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func until(d time.Duration, fn func()) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		fn()
	}
}

func mem() (rss, heap uint64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return rssBytes(), ms.HeapAlloc
}

func rssBytes() uint64 {
	// Current RSS, not rusage.Maxrss (a peak, incompatible with the current-value
	// deltas SwiftTCP and smoltcp now report). Aligned with SwiftTCP/Linux: the
	// resident-page count from /proc/self/statm.
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/self/statm"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 2 {
				if pages, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return pages * uint64(os.Getpagesize())
				}
			}
		}
	}
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	rss := uint64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	return rss
}

func cpu() [2]float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return [2]float64{timeval(ru.Utime), timeval(ru.Stime)}
}

func timeval(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}

func finish(name string, wall float64, pin, bin, pout, bout, delivered, est uint64, cpu0, cpu1 [2]float64, rss0, rss1, h0, h1 uint64, notes string) result {
	if wall < 1e-9 {
		wall = 1e-9
	}
	user := cpu1[0] - cpu0[0]
	sys := cpu1[1] - cpu0[1]
	rssDelta := uint64(0)
	if rss1 > rss0 {
		rssDelta = rss1 - rss0
	}
	bpc := 0.0
	if est > 0 {
		bpc = float64(rssDelta) / float64(est)
	}
	return result{
		Stack: stackLabel, Scenario: name, DurationS: wall,
		PacketsIn: pin, BytesIn: bin, PacketsOut: pout, BytesOut: bout,
		DeliveredBytes: delivered, Established: est,
		PPS: float64(pin) / wall, Gbps: float64(bin) * 8 / wall / 1e9, AppGbps: float64(delivered) * 8 / wall / 1e9,
		CPUUserS: user, CPUSysS: sys, CPUCores: (user + sys) / wall,
		RSSBeforeBytes: rss0, RSSAfterBytes: rss1, RSSDeltaBytes: rssDelta,
		FootprintBeforeBytes: h0, FootprintAfterBytes: h1,
		BytesPerConnection: bpc, Notes: notes,
	}
}
