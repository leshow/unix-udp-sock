#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
};

pub use crate::cmsg::{AsPtr, EcnCodepoint, Source, Transmit};
use imp::LastSendError;
use tracing::warn;

mod cmsg;

#[path = "unix.rs"]
mod imp;

pub use imp::{UdpSocket, sync};
pub mod framed;

/// Maximum number of UDP packets that can be sent by the `sendmmsg`/`recvmmsg`
/// wrappers.  Note that, for supported platforms, the OS caps the batch size at
/// this value, but will not return an error, so this is just a suggested
/// maximum.
///
/// Presently, this is 1024 on Linux and FreeBSD, and 1 on platforms that don't
/// support `sendmmsg`/`recvmmsg`
pub const BATCH_SIZE_CAP: usize = imp::BATCH_SIZE_CAP;

/// Default number of UDP packets to send/receive at a time.
pub const DEFAULT_BATCH_SIZE: usize = imp::DEFAULT_BATCH_SIZE;

/// The capabilities a UDP socket supports on the current platform.
///
/// Query platform-specific UDP features like GSO (Generic Segmentation Offload)
/// and GRO (Generic Receive Offload). Create with [`UdpState::new()`] to detect
/// capabilities at runtime.
///
/// # Example
///
/// ```
/// use unix_udp_sock::UdpState;
///
/// let state = UdpState::new();
/// println!("Max GSO segments: {}", state.max_gso_segments());
/// println!("GRO segments: {}", state.gro_segments());
/// ```
#[derive(Debug)]
pub struct UdpState {
    max_gso_segments: AtomicUsize,
    gro_segments: usize,
}

impl UdpState {
    pub fn new() -> Self {
        imp::udp_state()
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        self.max_gso_segments.load(Ordering::Relaxed)
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub fn gro_segments(&self) -> usize {
        self.gro_segments
    }
}

impl Default for UdpState {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata about a received UDP datagram.
///
/// This structure provides detailed information about a received packet including
/// the sender's address, packet size, ECN codepoint, destination IP, and network
/// interface information.
///
/// Obtained from [`recv_msg`](UdpSocket::recv_msg) or [`recv_mmsg`](UdpSocket::recv_mmsg).
///
/// # Example
///
/// ```no_run
/// use unix_udp_sock::sync::UdpSocket;
///
/// # fn main() -> std::io::Result<()> {
/// let socket = UdpSocket::bind("0.0.0.0:8080")?;
/// let mut buf = [0u8; 1500];
/// let meta = socket.recv_msg(&mut buf)?;
///
/// println!("From: {}", meta.addr);
/// println!("Length: {} bytes", meta.len);
/// if let Some(dst) = meta.dst_ip {
///     println!("Destination IP: {}", dst);
/// }
/// if let Some(ecn) = meta.ecn {
///     println!("ECN: {:?}", ecn);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    /// address we received datagram on
    pub addr: SocketAddr,
    /// length of datagram
    pub len: usize,
    /// The stride for GRO (Generic Receive Offload) packets, 0 otherwise
    pub stride: usize,
    /// The ECN (Explicit Congestion Notification) codepoint, if available
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address for this datagram (ipi_addr)
    pub dst_ip: Option<IpAddr>,
    /// The destination local IP address for this datagram (ipi_spec_dst)
    pub dst_local_ip: Option<IpAddr>,
    /// interface index that datagram was received on
    pub ifindex: u32,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            dst_local_ip: None,
            ifindex: 0,
        }
    }
}

/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: u64 = 60;

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
fn log_sendmsg_error<B: AsPtr<u8>>(
    last_send_error: LastSendError,
    err: impl core::fmt::Debug,
    transmit: &Transmit<B>,
) {
    if last_send_error.should_log() {
        warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            transmit.dst,
            transmit.src,
            transmit.ecn,
            transmit.contents.len(),
            transmit.segment_size
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_create() {
        let s = sync::UdpSocket::bind("0.0.0.0:9909");
        assert!(s.is_ok());
    }
    #[test]
    fn test_send_recv() {
        let saddr = "0.0.0.0:9901".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let buf = b"hello world";
        b.send_to(&buf[..], saddr).unwrap();
        // recv
        let mut r = [0; 1024];
        a.recv_from(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
    }
    #[test]
    fn test_send_recv_msg() {
        let saddr = "0.0.0.0:9902".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let send_port = b.local_addr().unwrap().port();
        let send_addr = b.local_addr().unwrap().ip();
        let buf = b"hello world";
        let src = Source::Interface(1);
        let tr = Transmit::new(saddr, *buf).src_ip(src);
        b.send_msg(&UdpState::new(), tr).unwrap();
        // recv
        let mut r = [0; 1024];
        let meta = a.recv_msg(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
        // dst addr and b addr matches!
        // meta.ifindex
        assert_eq!(send_port, meta.addr.port());
        assert_eq!(meta.ifindex, 1);
        assert!(matches!(
            meta.dst_local_ip,
            // dst_local_ip might be 127.0.0.1
            Some(addr) if addr == send_addr || addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }
    #[test]
    fn test_send_recv_msg_ip() {
        let saddr = "0.0.0.0:9903".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let send_port = b.local_addr().unwrap().port();
        let send_addr = b.local_addr().unwrap().ip();
        let buf = b"hello world";
        let src = Source::Ip("0.0.0.0".parse().unwrap());
        let tr = Transmit::new(saddr, *buf).src_ip(src);
        b.send_msg(&UdpState::new(), tr).unwrap();
        // recv
        let mut r = [0; 1024];
        let meta = a.recv_msg(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
        // dst addr and b addr matches!
        // meta.ifindex
        assert_eq!(send_port, meta.addr.port());
        assert_eq!(meta.ifindex, 1);
        assert!(matches!(
            meta.dst_local_ip,
            // dst_local_ip might be 127.0.0.1
            Some(addr) if addr == send_addr || addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

    // README example tests
    #[test]
    fn test_send_recv_msg_sync() {
        let socket = sync::UdpSocket::bind("127.0.0.1:0").unwrap();
        let state = UdpState::new();
        let dest = socket.local_addr().unwrap();

        // Send with custom source IP and ECN marking
        let data = b"hello world";
        let transmit = Transmit::new(dest, *data)
            .src_ip(Source::Ip("127.0.0.1".parse().unwrap()))
            .ecn(EcnCodepoint::Ect0);

        socket.send_msg(&state, transmit).unwrap();

        // Receive with full metadata
        let mut buf = [0u8; 1500];
        let meta = socket.recv_msg(&mut buf).unwrap();

        assert_eq!(&buf[..meta.len], b"hello world");
        assert_eq!(meta.ecn, Some(EcnCodepoint::Ect0));
    }

    #[tokio::test]
    async fn test_send_recv_msg_async() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let state = UdpState::new();
        let dest = socket.local_addr().unwrap();

        // Send with custom source IP and ECN marking
        let data = b"hello world";
        let transmit = Transmit::new(dest, *data)
            .src_ip(Source::Ip("127.0.0.1".parse().unwrap()))
            .ecn(EcnCodepoint::Ect0);

        socket.send_msg(&state, transmit).await.unwrap();

        // Receive with full metadata
        let mut buf = [0u8; 1500];
        let meta = socket.recv_msg(&mut buf).await.unwrap();

        assert_eq!(&buf[..meta.len], b"hello world");
        assert_eq!(meta.ecn, Some(EcnCodepoint::Ect0));
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn test_send_recv_mmsg_sync() {
        use std::io::IoSliceMut;

        // Test blocking socket with exact batch size matching packet count
        let a = sync::UdpSocket::bind("127.0.0.1:9905").unwrap();
        let b = sync::UdpSocket::bind("127.0.0.1:0").unwrap();
        let state = UdpState::new();
        let dest = a.local_addr().unwrap();

        // Send 2 packets
        let packets = [
            Transmit::new(dest, [1, 2, 3, 4]),
            Transmit::new(dest, [5, 6, 7, 8]),
        ];
        let sent = b.send_mmsg(&state, &packets).unwrap();

        // Receive with batch size of 2 to match packet count
        // With msg-waitforone: blocks for first packet, returns with all available
        // Without msg-waitforone: would block until exactly 2 packets arrive
        let mut bufs = [[0u8; 10]; 2];
        let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();
        let mut meta = [RecvMeta::default(); 2];
        let received = a
            .recv_mmsg_with_batch_size::<2>(&mut slices, &mut meta)
            .unwrap();

        assert_eq!(sent, 2);
        assert_eq!(received, 2);
        assert_eq!(&bufs[0][..4], &[1, 2, 3, 4]);
        assert_eq!(&bufs[1][..4], &[5, 6, 7, 8]);
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[tokio::test]
    async fn test_send_recv_mmsg_async() {
        use std::io::IoSliceMut;

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let state = UdpState::new();
        let dest = a.local_addr().unwrap();

        // Send multiple packets in one syscall
        let packets = [
            Transmit::new(dest, [1, 2, 3, 4]),
            Transmit::new(dest, [5, 6, 7, 8]),
        ];
        let sent = b.send_mmsg(&state, &packets).await.unwrap();
        assert_eq!(sent, 2);

        // Receive multiple packets in one syscall
        let mut bufs = [[0u8; 1500]; 2];
        let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();
        let mut meta = [RecvMeta::default(); 10];
        let received = a.recv_mmsg(&mut slices, &mut meta).await.unwrap();

        assert_eq!(received, 2);
        assert_eq!(&bufs[0][..4], &[1, 2, 3, 4]);
        assert_eq!(&bufs[1][..4], &[5, 6, 7, 8]);
    }
}
