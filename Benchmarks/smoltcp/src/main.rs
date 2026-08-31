use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::VecDeque;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];

struct Counters {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
}

struct BenchDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    counters: Arc<Counters>,
    caps: DeviceCapabilities,
}

impl BenchDevice {
    fn new() -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            counters: Arc::new(Counters {
                tx_packets: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
            }),
            caps,
        }
    }
}

struct RxTok {
    buffer: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct TxTok {
    tx: *mut VecDeque<Vec<u8>>,
    counters: Arc<Counters>,
}

impl TxToken for TxTok {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.counters.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        unsafe { (*self.tx).push_back(buf) };
        r
    }
}

impl Device for BenchDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        let tx = TxTok {
            tx: &mut self.tx as *mut _,
            counters: Arc::clone(&self.counters),
        };
        Some((RxTok { buffer }, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok {
            tx: &mut self.tx as *mut _,
            counters: Arc::clone(&self.counters),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

struct Bench {
    device: BenchDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    handles: Vec<SocketHandle>,
    delivered: u64,
}

impl Bench {
    fn new(socket_count: usize, window: usize) -> Self {
        let mut device = BenchDevice::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x00c0_ffee;
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 24))
                .unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut handles = Vec::with_capacity(socket_count);
        for _ in 0..socket_count {
            let rx = SocketBuffer::new(vec![0u8; window]);
            let tx = SocketBuffer::new(vec![0u8; window]);
            let mut socket = TcpSocket::new(rx, tx);
            socket.listen(80).unwrap();
            handles.push(sockets.add(socket));
        }
        Self {
            device,
            iface,
            sockets,
            handles,
            delivered: 0,
        }
    }

    fn poll(&mut self) {
        let now = Instant::now();
        self.iface
            .poll(now, &mut self.device, &mut self.sockets);
        for h in &self.handles {
            let s = self.sockets.get_mut::<TcpSocket>(*h);
            if s.can_recv() {
                if let Ok(n) = s.recv(|data| {
                    let n = data.len();
                    (n, n)
                }) {
                    self.delivered += n as u64;
                }
            }
            if !s.is_open() {
                let _ = s.listen(80);
            }
        }
    }

    fn inject(&mut self, pkt: Vec<u8>) {
        self.device.rx.push_back(pkt);
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.tx.drain(..).collect()
    }
}

#[derive(Clone, Copy)]
struct Peer {
    port: u16,
    client_seq: u32,
    iss: u32,
}

fn handshake(b: &mut Bench, port: u16, iss: u32) -> Peer {
    b.inject(ipv4_tcp(port, 80, iss, 0, SYN, &[], 65535, &syn_opts()));
    b.poll();
    let tx = b.drain_tx();
    let synack = tx
        .iter()
        .find(|p| p.len() >= 40 && p[33] & SYN != 0 && p[33] & ACK != 0)
        .expect("SYN-ACK");
    let server_iss = u32::from_be_bytes(synack[24..28].try_into().unwrap());
    let client_seq = iss.wrapping_add(1);
    b.inject(ipv4_tcp(port, 80, client_seq, server_iss.wrapping_add(1), ACK, &[], 65535, &[]));
    b.poll();
    let _ = b.drain_tx();
    Peer {
        port,
        client_seq,
        iss: server_iss,
    }
}

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn syn_opts() -> Vec<u8> {
    vec![2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7]
}

fn ipv4_tcp(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    window: u16,
    opts: &[u8],
) -> Vec<u8> {
    let mut options = opts.to_vec();
    while options.len() % 4 != 0 {
        options.push(1);
    }
    let tcp_hdr = 20 + options.len();
    let total = 20 + tcp_hdr + payload.len();
    let mut b = vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    b[8] = 64;
    b[9] = 6;
    b[12..16].copy_from_slice(&CLIENT);
    b[16..20].copy_from_slice(&SERVER);
    b[20..22].copy_from_slice(&sport.to_be_bytes());
    b[22..24].copy_from_slice(&dport.to_be_bytes());
    b[24..28].copy_from_slice(&seq.to_be_bytes());
    b[28..32].copy_from_slice(&ack.to_be_bytes());
    b[32] = ((tcp_hdr / 4) as u8) << 4;
    b[33] = flags;
    b[34..36].copy_from_slice(&window.to_be_bytes());
    b[40..40 + options.len()].copy_from_slice(&options);
    b[20 + tcp_hdr..].copy_from_slice(payload);
    let ip_csum = inet_checksum(&b[..20]);
    b[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let tcp_csum = tcp_checksum(&b[20..], CLIENT, SERVER);
    b[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    b
}

fn ipv4_icmp_echo(payload: usize) -> Vec<u8> {
    let body = vec![b'p'; payload];
    let total = 20 + 8 + body.len();
    let mut b = vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    b[8] = 64;
    b[9] = 1;
    b[12..16].copy_from_slice(&CLIENT);
    b[16..20].copy_from_slice(&SERVER);
    b[20] = 8;
    b[28..].copy_from_slice(&body);
    let ip_csum = inet_checksum(&b[..20]);
    b[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_csum = inet_checksum(&b[20..]);
    b[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
    b
}

fn inet_checksum(p: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = p.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_checksum(tcp: &[u8], src: [u8; 4], dst: [u8; 4]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6 + tcp.len() as u32;
    let mut chunks = tcp.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultJson {
    stack: String,
    scenario: String,
    duration_s: f64,
    warmup_s: f64,
    connections: i64,
    payload_bytes: i64,
    batch: i64,
    loops: i64,
    window_bytes: i64,
    packets_in: u64,
    bytes_in: u64,
    packets_out: u64,
    bytes_out: u64,
    delivered_bytes: u64,
    established: u64,
    pps: f64,
    gbps: f64,
    app_gbps: f64,
    cpu_user_s: f64,
    cpu_sys_s: f64,
    cpu_cores: f64,
    rss_before_bytes: u64,
    rss_after_bytes: u64,
    rss_delta_bytes: u64,
    footprint_before_bytes: u64,
    footprint_after_bytes: u64,
    bytes_per_connection: f64,
    notes: String,
}

fn emit(r: ResultJson, output: Option<&str>, json: bool) {
    let s = serde_json::to_string_pretty(&vec![r]).unwrap();
    if let Some(path) = output {
        std::fs::write(path, format!("{s}\n")).unwrap();
    }
    if json || output.is_none() {
        println!("{s}");
    }
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().expect("missing value");
        match k.as_str() {
            "--scenario" => a.scenario = v(),
            "--duration" => a.duration = v().parse::<f64>().unwrap(),
            "--warmup" => a.warmup = v().parse::<f64>().unwrap(),
            "--connections" => a.connections = v().parse().unwrap(),
            "--payload" => a.payload = v().parse().unwrap(),
            "--batch" => a.batch = v().parse().unwrap(),
            "--window" => a.window = v().parse().unwrap(),
            "--hold-conns" => a.hold = v().parse().unwrap(),
            "--json" => a.json = true,
            "--output" => a.output = Some(v()),
            "--active-conns" | "--rps-bytes" | "--loss" | "--stack" | "--loops" | "--algorithm" => {
                let _ = v();
            }
            _ => panic!("unknown flag {k}"),
        }
    }
    a
}

struct Args {
    scenario: String,
    duration: f64,
    warmup: f64,
    connections: usize,
    payload: usize,
    batch: usize,
    window: usize,
    hold: usize,
    json: bool,
    output: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            scenario: "tcp-rx".into(),
            duration: 5.0,
            warmup: 1.0,
            connections: 8,
            payload: 1460,
            batch: 64,
            window: 64 * 1024,
            hold: 4096,
            json: false,
            output: None,
        }
    }
}

fn rss_bytes() -> u64 {
    // Current RSS (resident page count from /proc/self/statm on Linux), aligned
    // with SwiftTCP's Linux branch and the gVisor harness. The previous rusage
    // Maxrss is a peak value and incompatible with current-value deltas.
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = s
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u64>().ok())
            {
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                return pages * page as u64;
            }
        }
    }
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let v = ru.ru_maxrss as u64;
    if cfg!(target_os = "linux") {
        v * 1024
    } else {
        v
    }
}

fn cpu_secs() -> (f64, f64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let to = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    (to(ru.ru_utime), to(ru.ru_stime))
}

fn finish(
    scenario: &str,
    wall: f64,
    pin: u64,
    bin: u64,
    pout: u64,
    bout: u64,
    delivered: u64,
    est: u64,
    cpu0: (f64, f64),
    cpu1: (f64, f64),
    rss0: u64,
    rss1: u64,
    a: &Args,
    notes: &str,
) -> ResultJson {
    let wall = wall.max(1e-9);
    let user = cpu1.0 - cpu0.0;
    let sys = cpu1.1 - cpu0.1;
    let conns = if scenario == "tcp-hold" {
        a.hold as i64
    } else {
        a.connections as i64
    };
    ResultJson {
        stack: "smoltcp".into(),
        scenario: scenario.into(),
        duration_s: wall,
        warmup_s: a.warmup,
        connections: conns,
        payload_bytes: a.payload as i64,
        batch: a.batch as i64,
        loops: 1,
        window_bytes: a.window as i64,
        packets_in: pin,
        bytes_in: bin,
        packets_out: pout,
        bytes_out: bout,
        delivered_bytes: delivered,
        established: est,
        pps: pin as f64 / wall,
        gbps: bin as f64 * 8.0 / wall / 1e9,
        app_gbps: delivered as f64 * 8.0 / wall / 1e9,
        cpu_user_s: user,
        cpu_sys_s: sys,
        cpu_cores: (user + sys) / wall,
        rss_before_bytes: rss0,
        rss_after_bytes: rss1,
        rss_delta_bytes: rss1.saturating_sub(rss0),
        footprint_before_bytes: rss0,
        footprint_after_bytes: rss1,
        bytes_per_connection: if est > 0 {
            (rss1.saturating_sub(rss0)) as f64 / est as f64
        } else {
            0.0
        },
        notes: notes.into(),
    }
}

fn until(seconds: f64, mut body: impl FnMut()) {
    let deadline = StdInstant::now() + Duration::from_secs_f64(seconds);
    while StdInstant::now() < deadline {
        body();
    }
}

fn main() {
    let mut a = parse_args();
    let mut payload = a.payload;
    let name = a.scenario.clone();
    if name == "tcp-rx-small" {
        payload = 64;
        a.payload = 64;
    }

    let r = match name.as_str() {
        "tcp-rx" | "tcp-rx-small" => run_tcp_rx(&a, &name, payload),
        "tcp-tx" => run_tcp_tx(&a),
        "tcp-cps" => run_tcp_cps(&a),
        "tcp-hold" => run_tcp_hold(&a),
        "icmp-echo" => run_icmp(&a),
        _ => panic!("unknown scenario {name}"),
    };
    emit(r, a.output.as_deref(), a.json);
}

fn run_tcp_rx(a: &Args, name: &str, payload: usize) -> ResultJson {
    let mut b = Bench::new(a.connections, a.window);
    let mut peers: Vec<Peer> = (0..a.connections)
        .map(|i| handshake(&mut b, 10000 + i as u16, 1000))
        .collect();
    let chunk = vec![b'a'; payload];
    let mut inject = |b: &mut Bench, peers: &mut [Peer]| {
        for i in 0..a.batch {
            let idx = i % peers.len();
            b.inject(ipv4_tcp(
                peers[idx].port,
                80,
                peers[idx].client_seq,
                peers[idx].iss.wrapping_add(1),
                ACK | PSH,
                &chunk,
                65535,
                &[],
            ));
            peers[idx].client_seq = peers[idx]
                .client_seq
                .wrapping_add(payload as u32);
        }
        b.poll();
        let _ = b.drain_tx();
    };
    until(a.warmup, || inject(&mut b, &mut peers));
    b.delivered = 0;
    b.device.counters.tx_packets.store(0, Ordering::Relaxed);
    b.device.counters.tx_bytes.store(0, Ordering::Relaxed);
    let rss0 = rss_bytes();
    let cpu0 = cpu_secs();
    let t0 = StdInstant::now();
    until(a.duration, || inject(&mut b, &mut peers));
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = cpu_secs();
    let rss1 = rss_bytes();
    let delivered = b.delivered;
    let segs = if payload > 0 { delivered / payload as u64 } else { 0 };
    finish(
        name,
        wall,
        segs,
        segs * (40 + payload as u64),
        b.device.counters.tx_packets.load(Ordering::Relaxed),
        b.device.counters.tx_bytes.load(Ordering::Relaxed),
        delivered,
        a.connections as u64,
        cpu0,
        cpu1,
        rss0,
        rss1,
        a,
        "RX bulk via smoltcp poll(); single-threaded",
    )
}

fn run_tcp_tx(a: &Args) -> ResultJson {
    let mut b = Bench::new(a.connections, a.window);
    let peers: Vec<Peer> = (0..a.connections)
        .map(|i| handshake(&mut b, 20000 + i as u16, 1000))
        .collect();
    let chunk = vec![b'b'; a.payload];
    let peer_seq: std::collections::HashMap<u16, u32> =
        peers.iter().map(|p| (p.port, p.client_seq)).collect();
    let handles = b.handles.clone();
    let mut pump_inner = |b: &mut Bench| {
        // Queue `batch` segments round-robin, matching Swift/gVisor tcp-tx.
        // The remote window advertises 65535 (no window-scaling, so ~64 KiB).
        for i in 0..a.batch {
            let h = handles[i % handles.len()];
            let s = b.sockets.get_mut::<TcpSocket>(h);
            if s.can_send() {
                let _ = s.send_slice(&chunk);
            }
        }
        // smoltcp's Interface::poll() emits at most ONE packet per socket per
        // egress phase (socket_egress dispatches each socket once). A single
        // poll would therefore throttle TX to a handful of packets/round and
        // starve the send buffer; loop poll() until the TX queue drains so the
        // whole batch actually leaves the stack.
        let mut rounds = 0;
        loop {
            b.poll();
            let tx = b.drain_tx();
            if tx.is_empty() {
                break;
            }
            for pkt in tx {
                if pkt.len() < 40 {
                    continue;
                }
                let doff = ((pkt[32] >> 4) as usize) * 4;
                let ip_pay =
                    u16::from_be_bytes(pkt[2..4].try_into().unwrap()) as usize - 20;
                let tcp_pay = ip_pay.saturating_sub(doff);
                if tcp_pay == 0 {
                    continue;
                }
                let pkt_src = u16::from_be_bytes(pkt[20..22].try_into().unwrap()); // server :80
                let pkt_dst = u16::from_be_bytes(pkt[22..24].try_into().unwrap()); // client ephemeral
                let seq = u32::from_be_bytes(pkt[24..28].try_into().unwrap());
                // ACK goes client -> server: source = pkt's dst port, dest = pkt's src port.
                // (The old code used pkt_src as both ports, so the ACK's 4-tuple matched
                // no socket and was dropped — the send window (~44 segments) drained once
                // and TX stalled at a few hundred pps.)
                let cseq = peer_seq.get(&pkt_dst).copied().unwrap_or(1);
                b.inject(ipv4_tcp(
                    pkt_dst,
                    pkt_src,
                    cseq,
                    seq.wrapping_add(tcp_pay as u32),
                    ACK,
                    &[],
                    65535,
                    &[],
                ));
            }
            rounds += 1;
            if rounds > 64 {
                break;
            }
        }
    };
    until(a.warmup, || pump_inner(&mut b));
    b.device.counters.tx_packets.store(0, Ordering::Relaxed);
    b.device.counters.tx_bytes.store(0, Ordering::Relaxed);
    let rss0 = rss_bytes();
    let cpu0 = cpu_secs();
    let t0 = StdInstant::now();
    until(a.duration, || pump_inner(&mut b));
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = cpu_secs();
    let rss1 = rss_bytes();
    let pout = b.device.counters.tx_packets.load(Ordering::Relaxed);
    let bout = b.device.counters.tx_bytes.load(Ordering::Relaxed);
    finish(
        "tcp-tx",
        wall,
        pout,
        bout,
        pout,
        bout,
        bout,
        a.connections as u64,
        cpu0,
        cpu1,
        rss0,
        rss1,
        a,
        "TX: send_slice(batch segments) + client ACK; single-threaded",
    )
}

fn run_tcp_cps(a: &Args) -> ResultJson {
    let mut b = Bench::new(a.batch.max(64), a.window);
    let mut port: u32 = 30000;
    let mut churn = |b: &mut Bench| {
        for _ in 0..a.batch {
            let p = handshake(b, port as u16, 1000);
            port += 1;
            if port > 60000 {
                port = 30000;
            }
            b.inject(ipv4_tcp(
                p.port,
                80,
                p.client_seq,
                p.iss.wrapping_add(1),
                RST | ACK,
                &[],
                0,
                &[],
            ));
            b.poll();
            let _ = b.drain_tx();
        }
    };
    until(1.0, || churn(&mut b));
    b.device.counters.tx_packets.store(0, Ordering::Relaxed);
    b.device.counters.tx_bytes.store(0, Ordering::Relaxed);
    let mut n = 0u64;
    let rss0 = rss_bytes();
    let cpu0 = cpu_secs();
    let t0 = StdInstant::now();
    until(a.duration, || {
        churn(&mut b);
        n += a.batch as u64;
    });
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = cpu_secs();
    let rss1 = rss_bytes();
    finish(
        "tcp-cps",
        wall,
        n * 3,
        n * 3 * 52,
        b.device.counters.tx_packets.load(Ordering::Relaxed),
        b.device.counters.tx_bytes.load(Ordering::Relaxed),
        0,
        n,
        cpu0,
        cpu1,
        rss0,
        rss1,
        a,
        "handshake + RST churn; sockets reused via listen()",
    )
}

fn run_tcp_hold(a: &Args) -> ResultJson {
    let rss0 = rss_bytes();
    let cpu0 = cpu_secs();
    let t0 = StdInstant::now();
    let mut b = Bench::new(a.hold, a.window);
    for i in 0..a.hold {
        handshake(&mut b, 10000 + i as u16, 1000);
    }
    std::thread::sleep(Duration::from_millis(200));
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = cpu_secs();
    let rss1 = rss_bytes();
    let est = b
        .handles
        .iter()
        .filter(|h| b.sockets.get::<TcpSocket>(**h).state() == State::Established)
        .count() as u64;
    finish(
        "tcp-hold",
        wall,
        a.hold as u64 * 2,
        a.hold as u64 * 2 * 52,
        b.device.counters.tx_packets.load(Ordering::Relaxed),
        b.device.counters.tx_bytes.load(Ordering::Relaxed),
        0,
        est,
        cpu0,
        cpu1,
        rss0,
        rss1,
        a,
        "idle ESTABLISHED; pre-allocated socket buffers dominate RSS",
    )
}

fn run_icmp(a: &Args) -> ResultJson {
    let mut b = Bench::new(1, a.window);
    let req = ipv4_icmp_echo(a.payload.max(8));
    let mut inject = |b: &mut Bench| {
        for _ in 0..a.batch {
            b.inject(req.clone());
        }
        b.poll();
        let _ = b.drain_tx();
    };
    until(a.warmup, || inject(&mut b));
    b.device.counters.tx_packets.store(0, Ordering::Relaxed);
    b.device.counters.tx_bytes.store(0, Ordering::Relaxed);
    let mut pkts = 0u64;
    let rss0 = rss_bytes();
    let cpu0 = cpu_secs();
    let t0 = StdInstant::now();
    until(a.duration, || {
        inject(&mut b);
        pkts += a.batch as u64;
    });
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = cpu_secs();
    let rss1 = rss_bytes();
    finish(
        "icmp-echo",
        wall,
        pkts,
        pkts * req.len() as u64,
        b.device.counters.tx_packets.load(Ordering::Relaxed),
        b.device.counters.tx_bytes.load(Ordering::Relaxed),
        b.device.counters.tx_bytes.load(Ordering::Relaxed),
        0,
        cpu0,
        cpu1,
        rss0,
        rss1,
        a,
        "ICMP echo flood; smoltcp replies if proto-ipv4 ICMP is enabled",
    )
}
