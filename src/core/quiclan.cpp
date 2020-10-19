/*
    Licensed under the MIT License.
*/
#include "precomp.h"

/*
    Questions:
    1) Does a new client get announced, or does the new client attempt to connect to all known peers?
    2) Does the client connect to all, or do all connnect to the client?
    3) if client announced, does this solve duplicate IP addresses?

    client Connects:
    1) authenticates to server (todo)
    2) requests external IP address
    3) Requests external/internal IP map of rest of swarm.
    4) announces selected internal IP mapped with external IP.
*/

const QUIC_REGISTRATION_CONFIG RegConfig = { "quiclan", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quiclan-00") - 1, (uint8_t*)"quiclan-00" };
const uint16_t UdpPort = 7490;
const uint64_t IdleTimeoutMs = 30000;
const uint64_t MaxBytesPerKey = 1000000;
const uint8_t DatagramsEnabled = TRUE;
const uint32_t KeepAliveMs = 5000;
const uint16_t BiDiStreamCount = 1;

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

    bool
    Send(
        _In_ QUIC_BUFFER* SendBuffer);

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

    uint16_t MaxDatagramLength = 1000; // TODO: calculate this as the min() of all connections' MTUs.

    bool ShuttingDown = false;
};

bool
QuicLanEngine::Initialize(
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler)
{
    QUIC_STATUS Status = MsQuicOpen(&MsQuic);
    if (QUIC_FAILED(Status)) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        return false;
    }

    Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
    if (QUIC_FAILED(Status)) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        return false;
    }

    this->EventHandler = EventHandler;

    return true;
};

QuicLanEngine::~QuicLanEngine() {

    if (MsQuic != nullptr) {
        if (Listener != nullptr) {
            MsQuic->ListenerClose(Listener);
        }
        for (auto Peer : Peers) {
            MsQuic->StreamClose(Peer->ControlStream);
            MsQuic->ConnectionClose(Peer->Connection);
        }
        if (ServerConfig != nullptr) {
            MsQuic->ConfigurationClose(ServerConfig);
        }
        if (ClientConfig != nullptr) {
            MsQuic->ConfigurationClose(ClientConfig);
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration); // Waits on all connections to be cleaned up.
        }
        MsQuicClose(MsQuic);
    }
};

bool
QuicLanEngine::StartClient()
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SETTINGS Settings{};
    QUIC_CREDENTIAL_CONFIG CredConfig{};
    QuicLanPeerContext* Peer = nullptr;
    //
    // Start a connection to an existing VPN, and wait for the connection
    // to complete before returning from this call.
    //
    Settings.IsSetFlags = 0;

    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = true;
    Settings.MaxBytesPerKey = MaxBytesPerKey;
    Settings.IsSet.MaxBytesPerKey = true;
    Settings.KeepAliveIntervalMs = KeepAliveMs;
    Settings.IsSet.KeepAliveIntervalMs = true;
    Settings.DatagramReceiveEnabled = true;
    Settings.IsSet.DatagramReceiveEnabled = true;

    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;  // TODO: Remove this eventually

    Status =
        MsQuic->ConfigurationOpen(
            Registration,
            &Alpn,
            1,
            &Settings,
            sizeof(Settings),
            nullptr,
            &ClientConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to open Client config 0x%x!\n", Status);
        goto Error;
    }

    Status =
        MsQuic->ConfigurationLoadCredential(
            ClientConfig,
            &CredConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to load client config, 0x%x!\n", Status);
        goto Error;
    }

    Peer = new QuicLanPeerContext;
    Peer->Engine = this;
    Status =
        MsQuic->ConnectionOpen(
            Registration,
            QuicLanEngine::ClientConnectionCallback,
            Peer,
            &Peer->Connection);
    if (QUIC_FAILED(Status)) {
        printf("Failed to open connection 0x%x\n", Status);
        goto Error;
    }

    Status =
        MsQuic->ConnectionStart(
            Peer->Connection,
            ClientConfig,
            AF_UNSPEC,
            ServerAddress,
            ServerPort);
    if (QUIC_FAILED(Status)) {
        printf("Failed to start connection 0x%x\n", Status);
        goto Error;
    }
    if (!AddPeer(Peer)) {
        goto Error;
    }
    Peer = nullptr;
Error:
    if (Peer != nullptr) {
        delete Peer;
    }
    return QUIC_SUCCEEDED(Status);
}

bool
QuicLanEngine::StartServer()
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SETTINGS Settings{};
    QUIC_CREDENTIAL_CONFIG CredConfig{};
    Settings.IsSetFlags = 0;

    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = true;
    Settings.MaxBytesPerKey = MaxBytesPerKey;
    Settings.IsSet.MaxBytesPerKey = true;
    Settings.KeepAliveIntervalMs = KeepAliveMs;
    Settings.IsSet.KeepAliveIntervalMs = true;
    Settings.DatagramReceiveEnabled = true;
    Settings.IsSet.DatagramReceiveEnabled = true;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = true;
    Settings.PeerBidiStreamCount = BiDiStreamCount;
    Settings.IsSet.PeerBidiStreamCount = true;

    QUIC_CERTIFICATE_FILE CertFile = {"key.pem", "cert.pem"};
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.CertificateFile = &CertFile;
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    Status =
        MsQuic->ConfigurationOpen(
            Registration,
            &Alpn,
            1,
            &Settings,
            sizeof(Settings),
            nullptr,
            &ServerConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to open security config, 0x%x!\n", Status);
        return false;
    }

    Status = MsQuic->ConfigurationLoadCredential(ServerConfig, &CredConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to load credential, 0x%x!\n", Status);
        return false;
    }

    Status =
        MsQuic->ListenerOpen(
            Registration,
            QuicLanEngine::ServerListenerCallback,
            this,
            &Listener);
    if (QUIC_FAILED(Status)) {
        printf("Failed to open listener, 0x%x\n", Status);
        return false;
    }

    QUIC_ADDR ListenAddress;
    QuicAddrSetFamily(&ListenAddress, AF_UNSPEC);
    QuicAddrSetPort(&ListenAddress, UdpPort);
    Status =
        MsQuic->ListenerStart(
            Listener,
            &Alpn,
            1,
            &ListenAddress); // TODO: Exclude VPN interface somehow?
    if (QUIC_FAILED(Status)) {
        printf("Failed to start listener, 0x%x\n", Status);
    }

    return QUIC_SUCCEEDED(Status);
}

bool
QuicLanEngine::Send(
    _In_ QUIC_BUFFER* SendBuffer)
{
    QuicLanPeerContext* FoundPeer = nullptr;
    {
        std::lock_guard ListLock(PeersLock);
        if (ShuttingDown) {
            goto Error;
        }
        struct ip* Ip4Header = nullptr;
        struct ip6_hdr* Ip6Header = nullptr;
        if ((SendBuffer->Buffer[0] & 0xF0) >> 4 == 4) {
            Ip4Header = (struct ip*) SendBuffer->Buffer;
            for (auto Peer : Peers) {
                if (memcmp(&Peer->InternalAddress4.Ipv4.sin_addr, &Ip4Header->ip_dst, sizeof(in_addr)) == 0) {
                    FoundPeer = Peer;
                    Peer->Lock.lock();
                    break;
                }
            }
        } else {
            assert((SendBuffer->Buffer[0] & 0xF0) >> 4 == 6);
            Ip6Header = (struct ip6_hdr*) SendBuffer->Buffer;
            for (auto Peer : Peers) {
                if (memcmp(&Peer->InternalAddress4.Ipv6.sin6_addr, &Ip6Header->ip6_dst, sizeof(in6_addr)) == 0) {
                    FoundPeer = Peer;
                    Peer->Lock.lock();
                    break;
                }
            }
        }
    }

    if (FoundPeer != nullptr) {
        QUIC_STATUS Status =
            MsQuic->DatagramSend(
                FoundPeer->Connection,
                SendBuffer,
                1,
                QUIC_SEND_FLAG_NONE,
                SendBuffer);
        FoundPeer->Lock.unlock();
        if (QUIC_FAILED(Status)) {
            goto Error;
        } else {
            return true;
        }
    } else {
Error:
        delete SendBuffer;
        // TODO: this leaks the app's memory
        return false;
    }
}

bool
QuicLanEngine::Stop()
{
    MsQuic->ListenerStop(Listener);
    // TODO: Inform all peers of the disconnect

    {
        std::lock_guard Lock(PeersLock);
        ShuttingDown = true;
        for (auto Peer : Peers) {
            MsQuic->ConnectionShutdown(
                Peer->Connection,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                0);
        }
    }

    return true;
}

_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event)
{
    auto This = (QuicLanEngine*)Context;

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        // TODO if (Event->NEW_CONNECTION->Info.LocalAddress == VPN tunnel address), drop
        QUIC_STATUS Status = This->MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, This->ServerConfig);
        if (QUIC_FAILED(Status)) {
            printf("Server failed to set config on client connection, 0x%x!\n", Status);
            return Status;
        }
        QuicLanPeerContext* PeerContext = new QuicLanPeerContext;
        PeerContext->ExternalAddress = *Event->NEW_CONNECTION.Info->RemoteAddress;
        PeerContext->Connection = Event->NEW_CONNECTION.Connection;
        PeerContext->ServerInitiated = true;
        PeerContext->Engine = This;
        if (This->AddPeer(PeerContext)) {
            This->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, PeerContext);
        } else {
            This->MsQuic->ConnectionClose(Event->NEW_CONNECTION.Connection);
            delete PeerContext;
        }
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    auto This = (QuicLanEngine*)Context;

    QuicLanTunnelEvent TunnelEvent{};

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Shutdown by peer, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        // TODO: Remove peer from list.
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        // TODO: Remove peer from list.
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        This->MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        // TODO: Open stream for authentication and control path
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // Take the datagram and send it over loopback to the VPN interface.
        // TODO: Check flags and if FIN flag set, close connection?
        TunnelEvent.Type = TunnelPacketReceived;
        TunnelEvent.PacketReceived.Packet = Event->DATAGRAM_RECEIVED.Buffer->Buffer;
        TunnelEvent.PacketReceived.PacketLength = Event->DATAGRAM_RECEIVED.Buffer->Length;
        This->EventHandler(&TunnelEvent); // TODO: Move this to a thread to not block QUIC.
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->MaxDatagramLength = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;

            // TODO: this is a hack just for development. Eventually, this will
            // pick an unused IP address based on the info from the control stream.
            TunnelEvent.Type = TunnelIpAddressReady;
            TunnelEvent.IpAddressReady.Mtu = This->MaxDatagramLength;
            // Client
            TunnelEvent.IpAddressReady.IPv4Addr = "169.254.10.2";
            TunnelEvent.IpAddressReady.IPv6Addr = "[fd71:7569:636c:616e::2]";
            This->EventHandler(&TunnelEvent);
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT) {
            TunnelEvent.Type = TunnelSendComplete;
            QUIC_BUFFER* Buffer = (QUIC_BUFFER*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            TunnelEvent.SendComplete.Packet = Buffer->Buffer;
            This->EventHandler(&TunnelEvent);
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
            delete Buffer;
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    auto This = (QuicLanPeerContext*)Context;
    QuicLanTunnelEvent TunnelEvent{};

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        This->Engine->MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Shutdown by peer, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        // TODO: Remove peer from list.
        // TODO: Remove context from list of contexts.
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        // TODO: Remove peer from list.
        // TODO: Remove context from list of contexts.
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        This->Engine->MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        // TODO: Authenticate client
        // TODO: start control stream
        This->ControlStream = Event->PEER_STREAM_STARTED.Stream;
        This->Engine->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QuicLanEngine::ServerControlStreamCallback, Context);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // Check that the packet is destined for this server, and send it to
        /// the VPN interface.
        // If not destined for this server, forward to the correct peer.
        // TODO: Check flags and if FIN flag set, close connection?
        TunnelEvent.Type = TunnelPacketReceived;
        TunnelEvent.PacketReceived.Packet = Event->DATAGRAM_RECEIVED.Buffer->Buffer;
        TunnelEvent.PacketReceived.PacketLength = Event->DATAGRAM_RECEIVED.Buffer->Length;
        This->Engine->EventHandler(&TunnelEvent); // TODO: Move this to a thread to not block QUIC.
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->Engine->MaxDatagramLength = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;

            // TODO: this is a hack just for development. Eventually, this will
            // pick an unused IP address based on the info from the control stream.
            TunnelEvent.Type = TunnelIpAddressReady;
            TunnelEvent.IpAddressReady.Mtu = This->Engine->MaxDatagramLength;
            // Server
            TunnelEvent.IpAddressReady.IPv4Addr = "169.254.10.1";
            TunnelEvent.IpAddressReady.IPv6Addr  = "[fd71:7569:636c:616e::1]";
            This->Engine->EventHandler(&TunnelEvent);
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT) {
            // TODO: Don't send event for forwarded datagrams.
            TunnelEvent.Type = TunnelSendComplete;
            QUIC_BUFFER* Buffer = (QUIC_BUFFER*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            TunnelEvent.SendComplete.Packet = Buffer->Buffer;
            This->Engine->EventHandler(&TunnelEvent);
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
            delete Buffer;
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ServerControlStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    // TODO:
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ClientControlStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    // TODO:
    return QUIC_STATUS_SUCCESS;
}

bool
Start(
    _In_ QuicLanEngine* Engine)
{
    if (strnlen(Engine->ServerAddress, sizeof(Engine->ServerAddress)) != 0) {
        //
        // Start a connection to an existing VPN, and wait for the connection
        // to complete before returning from this call.
        //
        if (!Engine->StartClient()) {
            return false;
        }
    }

    return Engine->StartServer();
}

bool
InitializeQuicLanEngine(
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler,
    _Out_ QuicLanEngine** Engine)
{
    *Engine = nullptr;

    QuicLanEngine* NewEngine = new QuicLanEngine;
    if (!NewEngine->Initialize(EventHandler)) {
        delete NewEngine;
        return false;
    }
    *Engine = NewEngine;
    return true;
}

bool
AddServer(
    _In_ QuicLanEngine* Engine,
    _In_ const char* ServerAddress,
    _In_ uint16_t ServerPort)
{
    strncpy(Engine->ServerAddress, ServerAddress, sizeof(Engine->ServerAddress));
    Engine->ServerPort = ServerPort;
    return true;
}

bool
Send(
    _In_ QuicLanEngine* Engine,
    _In_ const uint8_t* Packet,
    _In_ uint16_t PacketLength)
{
    // TODO: Don't allow the app to send unrestricted, apply back pressure from QUIC.
    // Consider forcing the app to request a buffer from us in a lookaside list
    // which allows us to apply back pressure.
    QUIC_BUFFER* Buffer = new QUIC_BUFFER;
    Buffer->Buffer = (uint8_t*) Packet;
    Buffer->Length = PacketLength;

    return Engine->Send(Buffer);
}

bool
Stop(
    _In_ QuicLanEngine* Engine)
{
    return Engine->Stop();
}

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine)
{
    delete Engine;
}
