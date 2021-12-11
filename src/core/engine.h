/*
    Licensed under the MIT License.
*/

const uint16_t MaxPacketLength = 1500;

struct QuicLanPeerContext {
    QuicLanEngine* Engine;
    HQUIC Connection;
    QUIC_ADDR ExternalAddress;
    QUIC_ADDR InternalAddress4; // TODO: Save client address here when they announce it.
    QUIC_ADDR InternalAddress6; // Ditto.
    struct {
        uint32_t IdUnknown : 1;
        uint32_t Connected : 1;
        uint32_t Authenticated : 1;
        uint32_t TimedOut : 1;
        uint32_t Disconnecting : 1;
        uint32_t Disconnected : 1;
    } State;
    uint32_t Server : 1;
    uint32_t Inserted : 1;
    uint32_t FirstConnection : 1;
    QuicLanMessageType LastMessageSent;
    uint16_t Mtu;
    uint16_t ID; // The low two bytes of the VPN IP address.
};

struct QuicLanControlStreamReceiveContext {
    QuicLanPeerContext* Peer;
    QUIC_BUFFER Data;
    uint32_t Offset;
    uint16_t HostId;
    QuicLanMessageType Type;
};

struct QuicLanEngine {

    bool
    Initialize(
        _In_z_ const char* Password,
        _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler,
        _In_ void* Context);

    bool
    StartClient();

    bool
    StartServer(
        _In_ uint16_t ListenerPort);

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

    void
    WorkerThreadProc();

    bool
    QueueWorkItem(
        _In_ const QuicLanWorkItem& WorkItem);

    bool
    ControlStreamSend(
        _In_ QuicLanPeerContext* Peer,
        _In_ QuicLanMessage* Message,
        _In_ const char* const Error);

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
    SendControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ReceiveControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    const QUIC_API_TABLE* MsQuic;
    HQUIC Registration;
    HQUIC ServerConfig;
    HQUIC ClientConfig;
    HQUIC Listener;

    FN_TUNNEL_EVENT_CALLBACK EventHandler;
    void* Context;

    std::string Password;

    char ServerAddress[255];
    uint16_t ServerPort;

    QUIC_ADDR Ip4VpnAddress;
    QUIC_ADDR Ip6VpnAddress;

    std::thread WorkerThread;
    std::list<QuicLanWorkItem> WorkItems;
    std::mutex WorkItemsLock;
    std::condition_variable WorkItemsCv;

    std::shared_mutex PeersLock;
    std::vector<QuicLanPeerContext*> Peers;

    std::mutex DatagramsOutstandingLock;
    std::condition_variable DatagramsOutstandingCv;
    uint16_t DatagramsOutstanding = 0;

    std::mutex StopLock;
    std::condition_variable StopCv;

    uint16_t MaxDatagramLength = MaxPacketLength; // Calculated as the min() of all connections' MTUs.

    uint16_t ID; // The low two bytes of the VPN IP address.

    bool ShuttingDown = false;
    bool IdRequested = false;
    bool IdAssigned = false;
};
