package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func runTCPDuplex(dur, warmup time.Duration, conns, payload, batch, window int) result {
	e := newEnv(window, true, true)
	defer e.close()
	e.autoAck.Store(true)
	writers := make([]*gonet.TCPConn, 0, conns)
	peers := make([]peer, conns)
	for i := 0; i < conns; i++ {
		p, err := handshake(e, uint16(21000+i), 1000, false)
		if err != nil {
			panic(err)
		}
		peers[i] = p
		writers = append(writers, takeConn(e))
	}
	txChunk := bytesOf('b', payload)
	rxChunk := bytesOf('a', payload)
	stop := make(chan struct{})
	defer close(stop)
	for _, c := range writers {
		c := c
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
					_, _ = c.Write(txChunk)
				}
			}
		}()
	}
	pump := func() {
		start := e.delivered.Load()
		for i := 0; i < batch; i++ {
			idx := i % conns
			e.inject(makeTCP(peers[idx], peers[idx].clientSeq, peers[idx].iss+1, header.TCPFlagAck|header.TCPFlagPsh, rxChunk))
			peers[idx].clientSeq += uint32(payload)
		}
		waitDelivered(e, start+uint64(batch*payload), 100*time.Millisecond)
	}
	until(warmup, pump)
	e.delivered.Store(0)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	e.txDataPackets.Store(0)
	e.txDataBytes.Store(0)
	return measure("tcp-duplex", dur, pump, e, uint64(conns), "full duplex: inbound PSH + concurrent gonet.Write; appGbps=RX (TX is concurrent, not serialized)", payload)
}

func runTCPRps(dur, warmup time.Duration, rpsBytes, payload, window int) result {
	e := newEnv(window, true, true)
	defer e.close()
	mss := payload
	if mss <= 0 || mss > 1460 {
		mss = 1460
	}
	port := uint32(30000)
	hs := make([]float64, 0, 4096)

	one := func() {
		pnum := uint16(port)
		port++
		if port > 60000 {
			port = 30000
		}
		t0 := time.Now()
		p, err := handshake(e, pnum, 1000, false)
		if err != nil {
			return
		}
		_ = takeConn(e)
		if len(hs) < 8192 {
			hs = append(hs, float64(time.Since(t0).Microseconds()))
		}
		start := e.delivered.Load()
		remaining := rpsBytes
		seq := p.clientSeq
		for remaining > 0 {
			n := mss
			if n > remaining {
				n = remaining
			}
			e.inject(makeTCP(p, seq, p.iss+1, header.TCPFlagAck|header.TCPFlagPsh, bytesOf('c', n)))
			seq += uint32(n)
			remaining -= n
		}
		e.inject(makeTCP(p, seq, p.iss+1, header.TCPFlagAck|header.TCPFlagFin, nil))
		waitDelivered(e, start+uint64(rpsBytes), 50*time.Millisecond)
	}

	until(warmup, one)
	e.completed.Store(0)
	e.delivered.Store(0)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	hs = hs[:0]
	var n uint64
	wrapped := func() {
		one()
		n++
	}
	res := measure("tcp-rps", dur, wrapped, e, e.accepts.Load(), "handshake + payload + FIN; rps = short connections started / s", payload)
	res.RPS = float64(n) / res.DurationS
	p50, p99 := percentilePair(hs)
	res.HandshakeP50Us, res.HandshakeP99Us = p50, p99
	res.PacketsIn = n * uint64((rpsBytes+mss-1)/mss+3)
	res.BytesIn = n * uint64(rpsBytes+3*52)
	res.PPS = float64(res.PacketsIn) / res.DurationS
	res.Gbps = float64(res.BytesIn) * 8 / res.DurationS / 1e9
	res.Established = e.accepts.Load()
	return res
}

func runTCPLatency(dur time.Duration, conns, payload, batch, window int) result {
	latInjected := new(uint64)
	e := newEnv(window, true, true)
	defer e.close()
	hs := make([]float64, 0, 512)
	fb := make([]float64, 0, 128)
	ingest := make([]float64, 0, 4096)
	port := uint32(40000)
	nextPort := func() uint16 {
		p := uint16(port)
		port++
		if port > 60000 {
			port = 40000
		}
		return p
	}

	skipHS := os.Getenv("GVS_LAT_SKIP_HS") != ""
	skipFB := os.Getenv("GVS_LAT_SKIP_FB") != ""
	if !skipHS {
		for i := 0; i < 256; i++ {
			t0 := time.Now()
			p, err := handshake(e, nextPort(), 1000, false)
			if err != nil {
				continue
			}
			_ = takeConn(e)
			hs = append(hs, float64(time.Since(t0).Microseconds()))
			e.inject(makeTCP(p, p.clientSeq, p.iss+1, header.TCPFlagRst|header.TCPFlagAck, nil))
		}
	}

	if !skipFB {
		for i := 0; i < 64; i++ {
			p, err := handshake(e, nextPort(), 1000, false)
			if err != nil {
				continue
			}
			_ = takeConn(e)
			before := e.delivered.Load()
			t0 := time.Now()
			e.inject(makeTCP(p, p.clientSeq, p.iss+1, header.TCPFlagAck|header.TCPFlagPsh, bytesOf('d', 64)))
			waitDelivered(e, before+64, 50*time.Millisecond)
			fb = append(fb, float64(time.Since(t0).Microseconds()))
			e.inject(makeTCP(p, p.clientSeq, p.iss+1, header.TCPFlagRst|header.TCPFlagAck, nil))
		}
	}

	peers := make([]peer, conns)
	for i := 0; i < conns; i++ {
		p, err := handshake(e, uint16(11000+i), 1000, false)
		if err != nil {
			panic(err)
		}
		peers[i] = p
		_ = takeConn(e)
	}
	chunk := bytesOf('a', payload)
	inject := func() {
		start := e.delivered.Load()
		t0 := time.Now()
		*latInjected += uint64(batch)
		for i := 0; i < batch; i++ {
			idx := i % conns
			e.inject(makeTCP(peers[idx], peers[idx].clientSeq, peers[idx].iss+1, header.TCPFlagAck|header.TCPFlagPsh, chunk))
			peers[idx].clientSeq += uint32(payload)
		}
		waitDelivered(e, start+uint64(batch*payload), 100*time.Millisecond)
		if len(ingest) < 8192 {
			ingest = append(ingest, float64(time.Since(t0).Microseconds()))
		}
	}
	e.delivered.Store(0)
	e.txPackets.Store(0)
	e.txBytes.Store(0)
	res := measure("tcp-latency", dur, inject, e, uint64(conns), "handshake / first-byte / ingest p50+p99 (µs); pps is the timed RX window", payload)
	if *latInjected > 10000 && res.DeliveredBytes < uint64(*latInjected)/100*uint64(payload) {
		fmt.Fprintf(os.Stderr, "WARN: tcp-latency delivered freezes (delivered=%d injected=%d); result invalid\n", res.DeliveredBytes, *latInjected)
		res.Notes = "INVALID: delivered froze during timed RX window; pps/gbps are 0"
		res.PacketsIn, res.PPS = 0, 0
		res.BytesIn, res.Gbps = 0, 0
		res.AppGbps = 0
	}
	h50, h99 := percentilePair(hs)
	f50, f99 := percentilePair(fb)
	i50, i99 := percentilePair(ingest)
	res.HandshakeP50Us, res.HandshakeP99Us = h50, h99
	res.FirstByteP50Us, res.FirstByteP99Us = f50, f99
	res.IngestP50Us, res.IngestP99Us = i50, i99
	return res
}

func percentilePair(values []float64) (p50, p99 float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := func(p float64) int {
		i := int(float64(len(sorted)-1)*p + 0.5)
		if i < 0 {
			i = 0
		}
		if i >= len(sorted) {
			i = len(sorted) - 1
		}
		return i
	}
	return sorted[idx(0.50)], sorted[idx(0.99)]
}

func ipv6TCP(sport, dport uint16, seq, ack uint32, flags header.TCPFlags, payload []byte, window uint16, opts []byte) []byte {
	if opts == nil {
		opts = []byte{}
	}
	for len(opts)%4 != 0 {
		opts = append(opts, 1)
	}
	tcpHdr := 20 + len(opts)
	total := 40 + tcpHdr + len(payload)
	b := make([]byte, total)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(tcpHdr+len(payload)))
	b[6] = 6
	b[7] = 64
	copy(b[8:24], clientIP6[:])
	copy(b[24:40], serverIP6[:])
	binary.BigEndian.PutUint16(b[40:], sport)
	binary.BigEndian.PutUint16(b[42:], dport)
	binary.BigEndian.PutUint32(b[44:], seq)
	binary.BigEndian.PutUint32(b[48:], ack)
	b[52] = byte((tcpHdr / 4) << 4)
	b[53] = uint8(flags)
	binary.BigEndian.PutUint16(b[54:], window)
	copy(b[60:], opts)
	copy(b[40+tcpHdr:], payload)
	binary.BigEndian.PutUint16(b[56:], tcpChecksum6(b[40:], clientIP6, serverIP6))
	return b
}

func tcpChecksum6(tcp []byte, src, dst [16]byte) uint16 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	plen := uint32(len(tcp))
	sum += plen >> 16
	sum += plen & 0xffff
	sum += 6 // next header
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
