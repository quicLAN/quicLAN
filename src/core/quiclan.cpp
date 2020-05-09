/*
    Licensed under the MIT License.
*/
#include "precomp.h"

const QUIC_REGISTRATION_CONFIG RegConfig = { "quiclan", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quiclan-00") - 1, (uint8_t*)"quiclan-00" };
const uint64_t IdleTimeoutMs = 25000;
const uint64_t MaxBytesPerKey = 1000000;
const uint8_t DatagramsEnabled = TRUE;
const uint32_t KeepAliveMs = 5000;
const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION; // TODO: Remove this eventually
const uint16_t BiDiStreamCount = 1;

struct QuicLanEngine {

    bool
    Initialize(
        _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler);

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
    ControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    const QUIC_API_TABLE* MsQuic;
    HQUIC Registration;
    HQUIC Session;
    QUIC_SEC_CONFIG* SecurityConfig;

    FN_TUNNEL_EVENT_CALLBACK EventHandler;

    char ServerAddress[255];
    uint16_t ServerPort;

    QUIC_EVENT ConnectedEvent;

    HQUIC PrimaryConnection;
    HQUIC Listener;
    std::vector<HQUIC> Peers;

    uint16_t MaxDatagramLength = 1000;
};

bool
QuicLanEngine::Initialize(
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler)
{
    QuicPlatformSystemLoad();

    QUIC_STATUS Status = QuicPlatformInitialize();
    if (QUIC_FAILED(Status)) {
        printf("QuicPlatformInitialize failed, 0x%x!\n", Status);
        return false;
    }

    Status = MsQuicOpen(&MsQuic);
    if (QUIC_FAILED(Status)) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        return false;
    }

    Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
    if (QUIC_FAILED(Status)) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        return false;
    }

    Status = MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session);
    if (QUIC_FAILED(Status)) {
        printf("SessionOpen failed, 0x%x!\n", Status);
        return false;
    }

    Status =
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_IDLE_TIMEOUT,
            sizeof(IdleTimeoutMs),
            &IdleTimeoutMs);
    if (QUIC_FAILED(Status)) {
        printf("SetParam(QUIC_PARAM_SESSION_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        return false;
    }

    Status =
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY,
            sizeof(MaxBytesPerKey),
            &MaxBytesPerKey);
    if (QUIC_FAILED(Status)) {
        printf("SetParam(QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY) failed, 0x%x!\n", Status);
        return false;
    }

    Status =
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED,
            sizeof(DatagramsEnabled),
            &DatagramsEnabled);
    if (QUIC_FAILED(Status)) {
        printf("SetParam(QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED) failed, 0x%x\n", Status);
        return false;
    }

    this->EventHandler = EventHandler;

    QuicEventInitialize(&ConnectedEvent, TRUE, FALSE);

    return true;
};

QuicLanEngine::~QuicLanEngine() {
    QuicEventUninitialize(ConnectedEvent);

    if (MsQuic != nullptr) {
        if (PrimaryConnection != nullptr) {
            MsQuic->ConnectionClose(PrimaryConnection);
        }
        for (HQUIC Peer : Peers) {
            MsQuic->ConnectionClose(Peer);
        }
        if (Session != nullptr) {
            MsQuic->SessionClose(Session); // Waits on all connections to be cleaned up.
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
};

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
        QUIC_STATUS Status =
            This->MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED,
                sizeof(DatagramsEnabled),
                &DatagramsEnabled);
        if (QUIC_FAILED(Status)) {
            printf("SetParam(QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED) failed, 0x%x!\n", Status);
        }
        Status =
            This->MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_KEEP_ALIVE,
                sizeof(KeepAliveMs),
                &KeepAliveMs);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set keep alive 0x%x\n", Status);
            return false;
        }
        Status =
            This->MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
                sizeof(BiDiStreamCount),
                &BiDiStreamCount);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set peer stream count 0x%x\n", Status);
            return false;
        }
        Event->NEW_CONNECTION.SecurityConfig = This->SecurityConfig;
        This->Peers.push_back(Event->NEW_CONNECTION.Connection); // TODO: be smarter about this.
        //Event->NEW_CONNECTION.Info->RemoteAddress // Map this to the connection/inner IP address
        This->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, This);
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

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        QuicEventSet(This->ConnectedEvent);
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
        // TODO: This will be the main workhorse when tunneled traffic flows.
        // Take the datagram and send it over loopback to the VPN interface.
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->MaxDatagramLength = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;

            // TODO: this is a hack just for development. Eventually, this will
            // pick an unused IP address based on the info from the control stream.
            QuicLanTunnelEvent Event{};
            Event.Type = TunnelIpAddressReady;
            Event.IpAddressReady.Mtu = This->MaxDatagramLength;
            // Client
            Event.IpAddressReady.IPv4Addr = "169.254.10.2";
            Event.IpAddressReady.IPv6Addr = "[fd71:7569:636c:616e::2]";
            This->EventHandler(&Event);
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
            QuicLanTunnelEvent TunnelEvent{};
            TunnelEvent.Type = TunnelSendComplete;
            TunnelEvent.SendComplete.Packet = (uint8_t*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            This->EventHandler(&TunnelEvent);
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
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
    auto This = (QuicLanEngine*)Context;

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        QuicEventSet(This->ConnectedEvent);
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
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        // TODO: Authenticate client
        // TODO: start control stream
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // TODO: This will be the main workhorse when tunneled traffic flows.
        // Check that the packet is destined for this server, and send it to
        /// the VPN interface.
        // If not destined for this server, forward to the correct peer.
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->MaxDatagramLength = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;

            // TODO: this is a hack just for development. Eventually, this will
            // pick an unused IP address based on the info from the control stream.
            QuicLanTunnelEvent Event{};
            Event.Type = TunnelIpAddressReady;
            Event.IpAddressReady.Mtu = This->MaxDatagramLength;
            // Server
            Event.IpAddressReady.IPv4Addr = "169.254.10.1";
            Event.IpAddressReady.IPv6Addr  = "[fd71:7569:636c:616e::1]";
            This->EventHandler(&Event);
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
            // TODO: Don't send event for forwarded datagrams.
            QuicLanTunnelEvent TunnelEvent{};
            TunnelEvent.Type = TunnelSendComplete;
            TunnelEvent.SendComplete.Packet = (uint8_t*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            This->EventHandler(&TunnelEvent);
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
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
QuicLanEngine::ControlStreamCallback(
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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (Engine->ServerAddress != nullptr) {
        //
        // Start a connection to an existing VPN, and wait for the connection
        // to complete before returning from this call.
        //
        HQUIC PrimaryConnection = nullptr;
        Status = Engine->MsQuic->ConnectionOpen(Engine->Session, QuicLanEngine::ClientConnectionCallback, Engine, &PrimaryConnection);
        if (QUIC_FAILED(Status)) {
            printf("Failed to open connection 0x%x\n", Status);
            return false;
        }

        Status =
            Engine->MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED,
                sizeof(DatagramsEnabled),
                &DatagramsEnabled);
        if (QUIC_FAILED(Status)) {
            printf("Failed to enable Datagrams on primary connection 0x%x\n", Status);
            return false;
        }

        Status =
            Engine->MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_KEEP_ALIVE,
                sizeof(KeepAliveMs),
                &KeepAliveMs);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set keep alive 0x%x\n", Status);
            return false;
        }

        Status =
            Engine->MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertificateValidationFlags),
                &CertificateValidationFlags);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set cert validation flags 0x%x\n", Status);
            return false;
        }

        Status =
            Engine->MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
                sizeof(BiDiStreamCount),
                &BiDiStreamCount);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set peer stream count 0x%x\n", Status);
            return false;
        }

        Status = Engine->MsQuic->ConnectionStart(PrimaryConnection, AF_UNSPEC, Engine->ServerAddress, Engine->ServerPort);
        if (QUIC_FAILED(Status)) {
            printf("Failed to start connection 0x%x\n", Status);
            return false;
        }
        Engine->PrimaryConnection = PrimaryConnection;
    }

    Status =
        Engine->MsQuic->ListenerOpen(
            Engine->Session,
            QuicLanEngine::ServerListenerCallback,
            Engine,
            &Engine->Listener);
    if (QUIC_FAILED(Status)) {
        printf("Failed to start listener, 0x%x\n", Status);
        return false;
    }

    Status =
        Engine->MsQuic->ListenerStart(
            Engine->Listener,
            nullptr); // TODO: Exclude VPN interface somehow?

    return true;
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

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine)
{
    delete Engine;
}
