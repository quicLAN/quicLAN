/*
    Licensed under the MIT License.
*/
struct QuicLanPeerContext;

enum QuicLanWorkItemType {
    Invalid = 0,
    AddPeer,
    ControlMessageReceived,
    ControlMessageSend,
    MtuChanged,
    ProcessState,
    ReceivePacket,
    RemovePeer,
    SendPacket,
    Shutdown,
    Exit
};

struct QuicLanWorkItem {
    QuicLanWorkItemType Type;
    union {
        struct {
            QuicLanPeerContext* Peer;
        } AddPeer;
        struct {
            QuicLanPeerContext* Peer;
            QUIC_BUFFER RecvData;
            uint16_t HostId;
            QuicLanMessageType Type;
        } ControlMessageRecv;
        struct {
            QuicLanPeerContext* Peer;
            QuicLanMessage* SendData;
            QuicLanMessageType Type;
        } ControlMessageSend;
        struct {
            QuicLanPeerContext* Peer;
            uint16_t NewMtu;
        } MtuChanged;
        struct {
            QuicLanPeerContext* Peer;
        } ProcessState;
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
