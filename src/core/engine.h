/*
    Licensed under the MIT License.
*/


struct QuicLanAuthBlock{
    uint8_t Len;
    char Pw[255];
};

struct QuicLanPeerContext {
    QuicLanEngine* Engine;
    HQUIC Connection;
    HQUIC ControlStream;
    QUIC_ADDR ExternalAddress;
    QUIC_ADDR InternalAddress4; // TODO: Save client address here when they announce it.
    QUIC_ADDR InternalAddress6; // Ditto.
    std::mutex Lock; // Lock to protect this from modification while being used.
    struct {
        uint32_t AddressReserved : 1;
        uint32_t Connected : 1;
        uint32_t Authenticating : 1;
        uint32_t AuthenticationFailed : 1;
        uint32_t Authenticated : 1;
        uint32_t ControlStreamOpen : 1;
        uint32_t ControlStreamClosed : 1;
        uint32_t TimedOut : 1;
        uint32_t Disconnected : 1;
    } State;
    uint32_t Server : 1;
    uint32_t Inserted : 1;
    uint32_t FirstConnection : 1;
    QuicLanMessageType LastMessageSent;
    uint16_t Mtu;
    uint16_t ID; // The low two bytes of the VPN IP address.
};

struct QuicLanEngine {

    bool
    Initialize(
        _In_z_ const char* Password,
        _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler);

    bool
    StartClient();

    bool
    StartServer(
        _In_ uint16_t ListenerPort);

    void
    ClientAuthenticationStart(
        _In_ HQUIC AuthStream,
        _In_ QuicLanPeerContext* PeerContext);

    bool AddPeer(_In_ QuicLanPeerContext* Peer) {std::lock_guard Lock(PeersLock); if (ShuttingDown) return false; Peers.push_back(Peer); Peer->Inserted = true; return true;}
    bool RemovePeer(_In_ QuicLanPeerContext* Peer) {std::lock_guard Lock(PeersLock); if (ShuttingDown) return false; auto it = Peers.begin(); while(*it != Peer) it++; if (it != Peers.end()) Peers.erase(it); Peer->Inserted = false; return true;}

    void
    IncrementOutstandingDatagrams();

    void
    DecrementOutstandingDatagrams();

    QuicLanPacket*
    GetPacket();

    bool
    Send(
        _In_ QuicLanPacket* SendBuffer);

    bool
    Stop();

    ~QuicLanEngine();

    static
    _Function_class_(QUIC_LISTENER_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerListenerCallback(
        _In_ HQUIC Listener,
        _In_opt_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event);

    static
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientConnectionCallback(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event);

    static
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerUnauthenticatedConnectionCallback(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event);

    static
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerAuthenticatedConnectionCallback(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerAuthStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientAuthStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);


    const QUIC_API_TABLE* MsQuic;
    HQUIC Registration;
    HQUIC ServerConfig;
    HQUIC ClientConfig;
    HQUIC Listener;

    FN_TUNNEL_EVENT_CALLBACK EventHandler;

    char Password[255];

    char ServerAddress[255];
    uint16_t ServerPort;

    QUIC_ADDR Ip4VpnAddress;
    QUIC_ADDR Ip6VpnAddress;

    std::mutex PeersLock;
    std::vector<QuicLanPeerContext*> Peers;

    std::mutex DatagramsOutstandingLock;
    std::condition_variable DatagramsOutstandingCv;
    uint16_t DatagramsOutstanding = 0;

    uint16_t MaxDatagramLength = 1500; // TODO: calculate this as the min() of all connections' MTUs.

    uint16_t ID; // The low two bytes of the VPN IP address.

    bool ShuttingDown = false;
};
