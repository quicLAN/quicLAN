/*
    Licensed under the MIT License.
*/
struct QuicLanPeerContext;

enum QuicLanWorkItemType {
    Invalid = 0,
    ControlMessageReceived,
    ControlMessageSend,
    MtuChanged,
    RemovePeer,
    AddPeer,
    ReceivePacket,
    SendPacket,
    Shutdown
};

struct QuicLanWorkItem {
    QuicLanWorkItemType Type;
    union {
        struct {
            QuicLanPeerContext* Peer;
        } AddPeer;
        struct {
            QuicLanPeerContext* Peer;
            union {
                QUIC_BUFFER RecvData;
                QuicLanMessage* SendData;
            };
            uint16_t HostId;
            QuicLanMessageType Type;
        } ControlMessage;
        struct {
            QuicLanPeerContext* Peer;
            uint16_t NewMtu;
        } MtuChanged;
        struct {
            QUIC_BUFFER Packet;
        } RecvPacket;
        struct {
            QuicLanPeerContext* Peer;
            QUIC_STATUS ShutdownError;
            uint8_t ShutdownPeer : 1;
        } RemovePeer;
        struct {
            QuicLanPacket* Packet;
        } SendPacket;
    };
};
