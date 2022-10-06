# unix-udp-sock

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
