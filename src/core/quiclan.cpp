#include "pch.h"

const QUIC_REGISTRATION_CONFIG RegConfig = { "quiclan", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quiclan-00") - 1, (uint8_t*)"quiclan-00" };
const uint64_t IdleTimeoutMs = 25000;
const uint64_t MaxBytesPerKey = 1000000;
const uint8_t DatagramsEnabled = TRUE;
const uint32_t KeepAliveMs = 5000;
const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION; // TODO: Remove this eventually
const uint16_t BiDiStreamCount = 1;

#define THROW_MSQUIC_ERROR(__Error, __Message) throw std::system_error(std::error_code((int)__Error, std::system_category()), __Message)

bool
QuicLanServer::Initialize() {
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

    QuicEventInitialize(&ConnectedEvent, TRUE, FALSE);

    return true;
};

QuicLanServer::~QuicLanServer() {
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
QuicLanServer::ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event)
{
    auto This = (QuicLanServer*)Context;

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        QUIC_STATUS Status =
            This->MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAMS,
                sizeof(DatagramsEnabled),
                &DatagramsEnabled);
        if (QUIC_FAILED(Status)) {
            printf("SetParam(QUIC_PARAM_CONN_DATAGRAMS) failed, 0x%x!\n", Status);
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
        This->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ClientConnectionCallback, This);
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
QuicLanServer::ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    auto This = (QuicLanServer*)Context;

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
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // TODO: This will be the main workhorse when tunneled traffic flows.
        // Take the datagram and send it over loopback to the VPN interface.
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_MAX_LENGTH_CHANGED:
        This->MaxDatagramLength = Event->DATAGRAM_MAX_LENGTH_CHANGED.Length;
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
        case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
        case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
        case QUIC_DATAGRAM_SEND_CANCELED:
            // TODO: Free the datagram send buffer.
            break;
        default:
            break;
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
QuicLanServer::ControlStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    // TODO: 
    return QUIC_STATUS_SUCCESS;
}

bool
QuicLanServer::Connect(
    _In_opt_ const char* ServerAddress,
    _In_opt_ uint16_t ServerPort,
    _Out_ char* ClientIpv4Addr,
    _Out_ char* ClientIpv6Addr)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (ServerAddress != nullptr) {
        //
        // Start a connection to an existing VPN, and wait for the connection
        // to complete before returning from this call.
        //
        HQUIC PrimaryConnection = nullptr;
        Status = MsQuic->ConnectionOpen(Session, QuicLanServer::ClientConnectionCallback, this, &PrimaryConnection);
        if (QUIC_FAILED(Status)) {
            printf("Failed to open connection 0x%x\n", Status);
            return false;
        }

        Status =
            MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAMS,
                sizeof(DatagramsEnabled),
                &DatagramsEnabled);
        if (QUIC_FAILED(Status)) {
            printf("Failed to enable Datagrams on primary connection 0x%x\n", Status);
            return false;
        }

        Status =
            MsQuic->SetParam(
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
            MsQuic->SetParam(
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
            MsQuic->SetParam(
                PrimaryConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
                sizeof(BiDiStreamCount),
                &BiDiStreamCount);
        if (QUIC_FAILED(Status)) {
            printf("Failed to set peer stream count 0x%x\n", Status);
            return false;
        }

        Status = MsQuic->ConnectionStart(PrimaryConnection, AF_UNSPEC, ServerAddress, ServerPort);
        if (QUIC_FAILED(Status)) {
            printf("Failed to start connection 0x%x", Status);
            return false;
        }

        if (!QuicEventWaitWithTimeout(ConnectedEvent, IdleTimeoutMs)) {
            printf("Failed to connect within timeout");
            return false;
        }
        ClientIpv4Addr = "169.254.10.2";
        ClientIpv6Addr = "[fd71:7569:636c:616e::2]";
    }
    else {
        ClientIpv4Addr = "169.254.10.1";
        ClientIpv6Addr = "[fd71:7569:636c:616e::1]";
    }



    return true;
}

void
SetVpnClientPort(
    _In_ uint16_t ClientPort)
{
    // TODO:
}