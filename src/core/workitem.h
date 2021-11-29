/*
    Licensed under the MIT License.
*/
struct QuicLanPeerContext;

enum QuicLanWorkItemType {
    Invalid = 0,
    ControlMessageReceived,
    ControlMessageSend,
    RemovePeer,
};

struct QuicLanWorkItem {
    QuicLanWorkItemType Type;
    union {
        struct {
            QuicLanPeerContext* Peer;
        } RemovePeer;
        struct {
            QuicLanPeerContext* Peer;
            union {
                QUIC_BUFFER RecvData;
                QuicLanMessage* SendData;
            };
            uint16_t HostId;
            uint8_t Type;
        } ControlMessage;
    };
};