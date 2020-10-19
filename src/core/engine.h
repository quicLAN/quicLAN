/*
    Licensed under the MIT License.
*/

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
        uint32_t StreamOpen : 1;
        uint32_t StreamClosed : 1;
        uint32_t TimedOut : 1;
        uint32_t Disconnected : 1;
    } State;
    uint32_t ServerInitiated : 1;
};

struct QuicLanEngine {

    bool
    Initialize(
        _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler);

    bool
    StartClient();

    bool
    StartServer();

    bool AddPeer(QuicLanPeerContext* Peer) {std::lock_guard Lock(PeersLock); if (ShuttingDown) return false; Peers.push_back(Peer); return true; }

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
    ServerConnectionCallback(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event);

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

    FN_TUNNEL_EVENT_CALLBACK EventHandler;

    char ServerAddress[255];
    uint16_t ServerPort;

    HQUIC Listener;
    std::mutex PeersLock;
    std::vector<QuicLanPeerContext*> Peers;

    std::mutex DatagramsOutstandingLock;
    std::condition_variable DatagramsOutstandingCv;
    uint16_t DatagramsOutstanding = 0;

    uint16_t MaxDatagramLength = 1400; // TODO: calculate this as the min() of all connections' MTUs.

    bool ShuttingDown = false;
};
