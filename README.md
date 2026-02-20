# unix-udp-sock

High-performance async and sync UDP sockets for Unix systems with advanced features.

Largely based on `quinn-udp`, this adds async & sync support for additional syscalls:

UDP socket send:

- `send_to` [libc](https://linux.die.net/man/2/sendto)
- `send` [libc](https://linux.die.net/man/2/send)
- `send_mmsg` [libc](https://linux.die.net/man/2/sendmmsg)
- `send_msg` [libc](https://linux.die.net/man/2/sendmsg)

UDP socket recv:

- `recv_from` [libc](https://linux.die.net/man/2/recvfrom)
- `recv` [libc](https://linux.die.net/man/2/recv)
- `recv_mmsg` [libc](https://linux.die.net/man/2/recvmmsg)
- `recv_msg` [libc](https://linux.die.net/man/2/recvmsg)

In addition, `Transmits` has been altered to support `Vec<u8>`/`[u8]`/`Bytes`/`BytesMut`.

We can also select which interface to use with `src_ip: Some(Source::Interface(idx))`. You must know the index of the interface to use this.

Also supports ECN, batch opts, GSO/GRO and metadata on recv.

This crate is designed for Unix-like systems:

- **Linux**: Full support including GSO/GRO, sendmmsg/recvmmsg
- **FreeBSD**: Full support including sendmmsg/recvmmsg
- **macOS**: Partial support (no GSO/GRO, no batch operations)

## Examples

### Send and Receive with Metadata (async)

```rust
use unix_udp_sock::{UdpSocket, Transmit, Source, UdpState, EcnCodepoint};

# #[tokio::main]
# async fn main() -> std::io::Result<()> {
let socket = UdpSocket::bind("0.0.0.0:0").await?;
let state = UdpState::new();
let dest = socket.local_addr()?;

// Send with custom source IP and ECN marking
let data = b"hello world";
let transmit = Transmit::new(dest, *data)
    .src_ip(Source::Ip("127.0.0.1".parse().unwrap()))
    .ecn(EcnCodepoint::Ect0);

socket.send_msg(&state, transmit).await?;

// Receive with full metadata
let mut buf = [0u8; 1500];
let meta = socket.recv_msg(&mut buf).await?;

assert_eq!(&buf[..meta.len], b"hello world");
println!("Received from: {}", meta.addr);
println!("Destination IP: {:?}", meta.dst_ip);
println!("Interface index: {}", meta.ifindex);
println!("ECN: {:?}", meta.ecn);
# Ok(())
# }
```

### Batch Operations Async (Linux/FreeBSD)

```rust
# #[cfg(any(target_os = "linux", target_os = "freebsd"))]
# async fn example() -> std::io::Result<()> {
use unix_udp_sock::{UdpSocket, Transmit, UdpState, RecvMeta};
use std::io::IoSliceMut;

let recv = UdpSocket::bind("127.0.0.1:0").await?;
let send = UdpSocket::bind("127.0.0.1:0").await?;
let state = UdpState::new();
let dest = recv.local_addr()?;

// Send multiple packets in one syscall
let packets = [
    Transmit::new(dest, [1, 2, 3, 4]),
    Transmit::new(dest, [5, 6, 7, 8]),
];
let sent = send.send_mmsg(&state, &packets).await?;
assert_eq!(sent, 2);

// Receive multiple packets in one syscall
let mut bufs = [[0u8; 1500]; 10];
let mut slices: Vec<IoSliceMut> = bufs.iter_mut()
    .map(|buf| IoSliceMut::new(buf))
    .collect();
let mut meta = [RecvMeta::default(); 10];
let received = recv.recv_mmsg(&mut slices, &mut meta).await?;

assert_eq!(received, 2);
assert_eq!(&bufs[0][..4], &[1, 2, 3, 4]);
assert_eq!(&bufs[1][..4], &[5, 6, 7, 8]);
# Ok(())
# }
```

## Performance Considerations

- Use `send_mmsg` and `recv_mmsg` for batch operations when available (Linux/FreeBSD)
- Enable GSO for sending large amounts of data efficiently on Linux
- Use `UdpState` to query platform capabilities at runtime
- Reuse buffers when possible to avoid allocations

## Blocking Socket Behavior (MSG_WAITFORONE)

By default, blocking (synchronous) `recv_mmsg` calls wait until exactly the batch size (default 10 or `recv_mmsg_with_batch_size` const param) number of packets arrive.

This crate provides an optional `msg-waitforone` feature that changes the behavior. It effects synchronous sockets **only**:

Without `msg-waitforone` feature (default):

- Blocking `recv_mmsg` waits until **exactly** the batch size number of packets arrive
- This can cause hangs if you request more packets than will be sent
- Non-blocking and async sockets are unaffected

With `msg-waitforone` feature enabled:

- Blocking `recv_mmsg` waits for the first packet, then returns with all immediately available packets (up to batch size)
- Non-blocking and async sockets are unaffected (they already return immediately)

`MSG_WAITFORONE` can improve performance if you're using synchronous sockets, but makes no difference with non-blocking sockets.

To enable:

```toml
[dependencies]
unix-udp-sock = { version = "0.9", features = ["msg-waitforone"] }
```

Enable if you use blocking sockets with `recv_mmsg` and want it to return as soon as at least one packet arrives, rather than waiting for the full batch size.

## License

MIT
