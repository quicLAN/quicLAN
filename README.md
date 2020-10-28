# quicLAN

A peer-to-peer VPN using IETF QUIC.

## Goals
quicLAN aims to enable secure peer-to-peer VPN over the internet using the latest secure protocol, [QUIC](https://quicwg.org/). To acheive this, quicLAN has the following goals:
- quicLAN will be cross-platform, initially targeting Microsoft Windows and Linux, and strives to be easy to adapt to other platforms.
- quicLAN will be resilient: if direct peer-to-peer connectivity cannot be established, it will attempt to route traffic through other peers.
- quicLAN will be secure, using strong cryptographic primitives to authenticate peers, and the underlying encryption built into QUIC to secure connections.
- quicLAN will be fast, using [MsQuic](https://github.com/Microsoft/msquic) for the underlying QUIC implementation.

## Contributing
At this time, quicLAN is not accepting external code contributions. However, interested parties are welcome to open issues.

## Disclaimers
quicLAN is a project in active development, and as such, no guarantees are made as to whether it is suitable for any particular use, nor whether it meets industry standards, or even acheives project goals.
quicLAN is not sponsored, endorsed, or developed for/by Microsoft, but does use Microsoft's MsQuic library.
