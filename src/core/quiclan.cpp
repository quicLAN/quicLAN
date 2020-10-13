/*
    Licensed under the MIT License.
*/
#include "precomp.h"

const QUIC_REGISTRATION_CONFIG RegConfig = { "quiclan", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quiclan-00") - 1, (uint8_t*)"quiclan-00" };
const uint16_t UdpPort = 7490;
const uint64_t IdleTimeoutMs = 30000;
const uint64_t MaxBytesPerKey = 1000000;
const uint8_t DatagramsEnabled = TRUE;
const uint32_t KeepAliveMs = 5000;
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
    HQUIC SecurityConfig;
    HQUIC ClientConfig;

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
        if (SecurityConfig != nullptr) {
            MsQuic->ConfigurationClose(SecurityConfig);
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration); // Waits on all connections to be cleaned up.
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
        QUIC_STATUS Status = This->MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, This->SecurityConfig);
        if (QUIC_FAILED(Status)) {
            printf("Server failed to set config on client connection, 0x%x!\n", Status);
            return Status;
        }
        This->Peers.push_back(Event->NEW_CONNECTION.Connection); // TODO: be smarter about this.
        //Event->NEW_CONNECTION.Info->RemoteAddress // Map this to the connection/inner IP address
        This->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, This);
        This->PrimaryConnection = Event->NEW_CONNECTION.Connection; // TODO: This is a hack for development.
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
    auto This = (QuicLanEngine*)Context;
    QuicLanTunnelEvent TunnelEvent{};

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
        // Check that the packet is destined for this server, and send it to
        /// the VPN interface.
        // If not destined for this server, forward to the correct peer.
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
            // Server
            TunnelEvent.IpAddressReady.IPv4Addr = "169.254.10.1";
            TunnelEvent.IpAddressReady.IPv6Addr  = "[fd71:7569:636c:616e::1]";
            This->EventHandler(&TunnelEvent);
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT) {
            // TODO: Don't send event for forwarded datagrams.
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
    QUIC_SETTINGS Settings{};
    QUIC_CREDENTIAL_CONFIG CredConfig{};
    if (strlen(Engine->ServerAddress) != 0) {
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
            Engine->MsQuic->ConfigurationOpen(
                Engine->Registration,
                &Alpn,
                1,
                &Settings,
                sizeof(Settings),
                nullptr,
                &Engine->ClientConfig);
        if (QUIC_FAILED(Status)) {
            printf("Failed to open Client config 0x%x!\n", Status);
            return false;
        }

        Status =
            Engine->MsQuic->ConfigurationLoadCredential(
                Engine->ClientConfig,
                &CredConfig);
        if (QUIC_FAILED(Status)) {
            printf("Failed to load client config, 0x%x!\n", Status);
            return false;
        }

        HQUIC PrimaryConnection = nullptr;
        Status = Engine->MsQuic->ConnectionOpen(
            Engine->Registration,
            QuicLanEngine::ClientConnectionCallback,
            Engine,
            &PrimaryConnection);
        if (QUIC_FAILED(Status)) {
            printf("Failed to open connection 0x%x\n", Status);
            return false;
        }


        Status = Engine->MsQuic->ConnectionStart(PrimaryConnection, Engine->ClientConfig, AF_UNSPEC, Engine->ServerAddress, Engine->ServerPort);
        if (QUIC_FAILED(Status)) {
            printf("Failed to start connection 0x%x\n", Status);
            return false;
        }
        Engine->PrimaryConnection = PrimaryConnection;
    }

    Settings.IsSetFlags = 0; // Reset from the client config

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
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = true;

    QUIC_CERTIFICATE_FILE CertFile = {"key.pem", "cert.pem"};
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.CertificateFile = &CertFile;
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    Status =
        Engine->MsQuic->ConfigurationOpen(
            Engine->Registration,
            &Alpn,
            1,
            &Settings,
            sizeof(Settings),
            nullptr,
            &Engine->SecurityConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to open security config, 0x%x!\n", Status);
        return false;
    }

    Status = Engine->MsQuic->ConfigurationLoadCredential(Engine->SecurityConfig, &CredConfig);
    if (QUIC_FAILED(Status)) {
        printf("Failed to load credential, 0x%x!\n", Status);
        return false;
    }

    Status =
        Engine->MsQuic->ListenerOpen(
            Engine->Registration,
            QuicLanEngine::ServerListenerCallback,
            Engine,
            &Engine->Listener);
    if (QUIC_FAILED(Status)) {
        printf("Failed to start listener, 0x%x\n", Status);
        return false;
    }

    QUIC_ADDR ListenAddress;
    QuicAddrSetFamily(&ListenAddress, AF_UNSPEC);
    QuicAddrSetPort(&ListenAddress, UdpPort);
    Status =
        Engine->MsQuic->ListenerStart(
            Engine->Listener,
            &Alpn,
            1,
            &ListenAddress); // TODO: Exclude VPN interface somehow?

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

bool
Send(
    _In_ QuicLanEngine* Engine,
    _In_ const uint8_t* Packet,
    _In_ uint16_t PacketLength)
{
    // TODO: lookup which connection to send this on based on IP address.
    // TODO: Don't allow the app to send unrestricted, apply back pressure from QUIC.
    QUIC_BUFFER* Buffer = new QUIC_BUFFER;
    Buffer->Buffer = (uint8_t*) Packet;
    Buffer->Length = PacketLength;

    QUIC_STATUS Status =
        Engine->MsQuic->DatagramSend(
            Engine->PrimaryConnection,
            Buffer,
            1,
            QUIC_SEND_FLAG_NONE,
            Buffer);

    if (QUIC_FAILED(Status)) {
        delete Buffer;
        return false;
    } else {
        return true;
    }
}

bool
Stop(
    _In_ QuicLanEngine* Engine)
{
    // TODO: Inform all peers of the disconnect
    Engine->MsQuic->ConnectionShutdown(
        Engine->PrimaryConnection,
        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
        0);

    for (HQUIC Peer : Engine->Peers) {
        Engine->MsQuic->ConnectionShutdown(
            Peer,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            0);
    }

    return true;
}

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine)
{
    delete Engine;
}
