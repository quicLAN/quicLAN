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

const uint32_t MaxDatagramsOutstanding = 50;

bool
QuicLanEngine::Initialize(
    _In_z_ const char* Password,
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
    strncpy(this->Password, Password, sizeof(this->Password));

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
    Settings.PeerBidiStreamCount = BiDiStreamCount;
    Settings.IsSet.PeerBidiStreamCount = true;

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
    // TODO: Hacks for development. Remove when implementing address announcements
    inet_aton("169.254.0.1", &Peer->InternalAddress4.Ipv4.sin_addr);
    inet_pton(AF_INET6, "[fd71:7569:636c:616e::1]", &Peer->InternalAddress6.Ipv6.sin6_addr);
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
QuicLanEngine::StartServer(
    _In_ uint16_t ListenerPort)
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
    QuicAddrSetPort(&ListenAddress, ListenerPort);
    Status =
        MsQuic->ListenerStart(
            Listener,
            &Alpn,
            1,
            &ListenAddress);
    if (QUIC_FAILED(Status)) {
        printf("Failed to start listener, 0x%x\n", Status);
    }

    if (strnlen(ServerAddress, sizeof(ServerAddress)) == 0) {
        // This is a server-only instance, so assign the first IP address.
        QuicLanTunnelEvent TunnelEvent{};
        TunnelEvent.Type = TunnelIpAddressReady;
        TunnelEvent.IpAddressReady.IPv4Addr = "169.254.0.1";
        TunnelEvent.IpAddressReady.IPv6Addr  = "[fd71:7569:636c:616e::1]";
        EventHandler(&TunnelEvent);
        inet_pton(AF_INET, TunnelEvent.IpAddressReady.IPv4Addr, &Ip4VpnAddress.Ipv4.sin_addr);
        inet_pton(AF_INET6, TunnelEvent.IpAddressReady.IPv6Addr, &Ip6VpnAddress.Ipv6.sin6_addr);
    }

    return QUIC_SUCCEEDED(Status);
}

void
QuicLanEngine::ClientAuthenticationStart(
    _In_ HQUIC AuthStream,
    _In_ QuicLanPeerContext* PeerContext)
{
    MsQuic->SetCallbackHandler(AuthStream, (void*)QuicLanEngine::ClientAuthStreamCallback, PeerContext);

    uint32_t PasswordLen = strnlen(Password, sizeof(Password));
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*) new uint8_t[sizeof(QUIC_BUFFER) + PasswordLen + 1];
    QuicLanAuthBlock* AuthBlock = (QuicLanAuthBlock*) (SendBuffer + 1);
    strncpy(AuthBlock->Pw, Password, PasswordLen);
    AuthBlock->Len = (uint8_t) PasswordLen;
    SendBuffer->Length = AuthBlock->Len + 1;
    SendBuffer->Buffer = (uint8_t*) AuthBlock;
    if (QUIC_FAILED(MsQuic->StreamSend(AuthStream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("Client failed to send authentication block!\n");
        // TODO: tear down connection
    }
}

void
QuicLanEngine::IncrementOutstandingDatagrams()
{
    std::lock_guard DOLock(DatagramsOutstandingLock);
    DatagramsOutstanding++;
}

void
QuicLanEngine::DecrementOutstandingDatagrams()
{
    std::unique_lock Lock(DatagramsOutstandingLock);
    DatagramsOutstanding--;
    Lock.unlock();
    DatagramsOutstandingCv.notify_one();
}

QuicLanPacket*
QuicLanEngine::GetPacket()
{
    std::unique_lock Lock(DatagramsOutstandingLock);
    while (DatagramsOutstanding >= MaxDatagramsOutstanding) {
        DatagramsOutstandingCv.wait(Lock);
    }
    Lock.unlock(); // We don't need the lock anymore.

    uint8_t* RawBuffer = new uint8_t[sizeof(QUIC_BUFFER) + MaxDatagramLength];
    QUIC_BUFFER* Buffer = (QUIC_BUFFER*)RawBuffer;
    Buffer->Buffer = RawBuffer + sizeof(QUIC_BUFFER);
    Buffer->Length = MaxDatagramLength;
    return Buffer;
}

bool
QuicLanEngine::Send(
    _In_ QuicLanPacket* SendBuffer)
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
            printf("DatagramSend failed! %u\n", Status);
            goto Error;
        } else {
            IncrementOutstandingDatagrams();
            return true;
        }
    } else {
        printf("Failed to find peer!\n");
Error:
        delete SendBuffer;
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
        // Reject connections to the VPN address. This isn't Inception.
        if ((Event->NEW_CONNECTION.Info->LocalAddress->Ip.sa_family == 4 && memcmp(&Event->NEW_CONNECTION.Info->LocalAddress->Ipv4.sin_addr, &This->Ip4VpnAddress.Ipv4.sin_addr, sizeof(This->Ip4VpnAddress.Ipv4.sin_addr)) == 0) ||
            (Event->NEW_CONNECTION.Info->LocalAddress->Ip.sa_family == 6 && memcmp(&Event->NEW_CONNECTION.Info->LocalAddress->Ipv6.sin6_addr, &This->Ip6VpnAddress.Ipv6.sin6_addr, sizeof(This->Ip6VpnAddress.Ipv6.sin6_addr))))
        {
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        QUIC_STATUS Status = This->MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, This->ServerConfig);
        if (QUIC_FAILED(Status)) {
            printf("Server failed to set config on client connection, 0x%x!\n", Status);
            return Status;
        }
        // TODO: find if the peer exists already (from an announcement) and use that context
        QuicLanPeerContext* PeerContext = new QuicLanPeerContext;
        PeerContext->ExternalAddress = *Event->NEW_CONNECTION.Info->RemoteAddress;
        PeerContext->Connection = Event->NEW_CONNECTION.Connection;
        PeerContext->Server = true;
        PeerContext->Engine = This;
        if (This->AddPeer(PeerContext)) {
            This->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerUnauthenticatedConnectionCallback, PeerContext);
        } else {
            delete PeerContext;
            return QUIC_STATUS_CONNECTION_REFUSED;
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
    auto This = (QuicLanPeerContext*)Context;

    QuicLanTunnelEvent TunnelEvent{};

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn][%p] Shutdown by peer, 0x%x\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            if (This->State.ControlStreamOpen && ! This->State.ControlStreamClosed) {
                This->Engine->MsQuic->StreamClose(This->ControlStream);
            }
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        // TODO: Open stream for control path
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        if (!This->State.Authenticated && !This->State.Authenticating) {
            This->Engine->ClientAuthenticationStart(Event->PEER_STREAM_STARTED.Stream, This);
        } else {
            // TODO: close the connection, the server tried to open a new stream
            // that is not the authentication stream
        }
        break;
    }
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // Take the datagram and send it over loopback to the VPN interface.
        // TODO: Check flags and if FIN flag set, close connection?
        TunnelEvent.Type = TunnelPacketReceived;
        TunnelEvent.PacketReceived.Packet = Event->DATAGRAM_RECEIVED.Buffer->Buffer;
        TunnelEvent.PacketReceived.PacketLength = Event->DATAGRAM_RECEIVED.Buffer->Length;
        This->Engine->EventHandler(&TunnelEvent); // TODO: Move this to a thread to not block QUIC.
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->Mtu = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT) {
            This->Engine->DecrementOutstandingDatagrams();
            uint8_t* Buffer = (uint8_t*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;

            delete [] Buffer; // TODO: Add buffer to a lookaside list
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
QuicLanEngine::ServerUnauthenticatedConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    auto This = (QuicLanPeerContext*)Context;
    QuicLanTunnelEvent TunnelEvent{};

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        printf("[conn][%p] Server Connected\n", Connection);
        // TODO: Hack for development. Remove when adding address announcements.
        inet_aton("169.254.10.2", &This->InternalAddress4.Ipv4.sin_addr);
        inet_pton(AF_INET6, "[fd71:7569:636c:616e::2]", &This->InternalAddress6.Ipv6.sin6_addr);
        HQUIC AuthStream;
        if (QUIC_FAILED(
                This->Engine->MsQuic->StreamOpen(
                    Connection,
                    QUIC_STREAM_OPEN_FLAG_NONE,
                    QuicLanEngine::ServerAuthStreamCallback,
                    Context,
                    &AuthStream))) {
            printf("Server Failed to open auth stream!\n");
        }
        if (QUIC_FAILED(
            This->Engine->MsQuic->StreamStart(AuthStream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            printf("Server Failed to start auth stream!\n");
        }
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn][%p] Shutdown by transport, 0x%x\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            if (This->State.ControlStreamOpen && ! This->State.ControlStreamClosed) {
                This->Engine->MsQuic->StreamClose(This->ControlStream);
            }
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        // TODO: kill connection; peer tried to start control stream before authenticating.
        return QUIC_STATUS_NOT_SUPPORTED;
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->Mtu = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
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
QuicLanEngine::ServerAuthenticatedConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    auto This = (QuicLanPeerContext*)Context;
    QuicLanTunnelEvent TunnelEvent{};

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn][%p] Shutdown by transport, 0x%x\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->RemovePeer(This);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            if (This->State.ControlStreamOpen && !This->State.ControlStreamClosed) {
                This->Engine->MsQuic->StreamClose(This->ControlStream);
            }
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        if (This->State.Authenticated) {
            This->ControlStream = Event->PEER_STREAM_STARTED.Stream;
            This->Engine->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QuicLanEngine::ServerControlStreamCallback, Context);
        } else {
            // TODO: kill connection; peer tried to start control stream before authenticating.
        }
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
            This->Mtu = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
            if (This->Mtu < This->Engine->MaxDatagramLength) {
                This->Engine->MaxDatagramLength = This->Mtu;
                // Inform the VPN that the MTU has changed.
                TunnelEvent.Type = TunnelMtuChanged;
                TunnelEvent.MtuChanged.Mtu = This->Mtu;
                This->Engine->EventHandler(&TunnelEvent);
            }
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED) {
            This->Engine->DecrementOutstandingDatagrams();
            uint8_t* Buffer = (uint8_t*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
            delete [] Buffer;
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
QuicLanEngine::ServerAuthStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    QuicLanPeerContext *This = (QuicLanPeerContext*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            printf("Server failed to start auth stream!\n");
            // TODO: shutdown the connection.
        }
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        if (Event->RECEIVE.BufferCount > 1) {
            printf("Server received %u buffers from client. Expected 1!\n", Event->RECEIVE.BufferCount);
        }
        QuicLanAuthBlock* AuthBlock = (QuicLanAuthBlock*) Event->RECEIVE.Buffers[0].Buffer;
        if (strnlen(AuthBlock->Pw, Event->RECEIVE.Buffers[0].Length - 1) != AuthBlock->Len ||
            AuthBlock->Len != strnlen(This->Engine->Password, sizeof(This->Engine->Password)) ||
            strncmp(AuthBlock->Pw, This->Engine->Password, Event->RECEIVE.Buffers[0].Length - 1)) {
            // Client-provided password doesn't match our password. Kill the connection!
            printf("Client password doesn't match our password! BufferLen: %u, %u != %u, %s != %s\n",
                Event->RECEIVE.Buffers[0].Length,
                AuthBlock->Len,
                strnlen(This->Engine->Password, sizeof(This->Engine->Password)),
                AuthBlock->Pw,
                This->Engine->Password);
            This->State.AuthenticationFailed = true;
            if (This->Engine->RemovePeer(This)) {
                This->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_STATUS_PERMISSION_DENIED);
                This->Engine->MsQuic->ConnectionShutdown(This->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_STATUS_PERMISSION_DENIED);
            }
        } else {
            // Client-provided password matches! Send our password in response and allow client to open control stream.
            This->State.Authenticated = true;
            QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*) new uint8_t[sizeof(QUIC_BUFFER) + Event->RECEIVE.Buffers[0].Length];
            SendBuffer->Length = Event->RECEIVE.Buffers[0].Length;
            SendBuffer->Buffer = (uint8_t*) (SendBuffer + 1);
            memcpy(SendBuffer->Buffer, AuthBlock, Event->RECEIVE.Buffers[0].Length);
            QUIC_SETTINGS Settings{};
            Settings.PeerBidiStreamCount = BiDiStreamCount;
            Settings.IsSet.PeerBidiStreamCount = true;

            This->Engine->MsQuic->SetCallbackHandler(This->Connection, (void*)ServerAuthenticatedConnectionCallback, This);
            This->Engine->MsQuic->ConnectionSendResumptionTicket(This->Connection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
            This->Engine->MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer);
            This->Engine->MsQuic->SetParam(
                This->Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SETTINGS,
                sizeof(Settings),
                &Settings);
            
            QuicLanTunnelEvent TunnelEvent{};
            // Now the client is authenticated and allowed to change MTU for the
            // entire tunnel.
            if (This->Mtu < This->Engine->MaxDatagramLength) {
                This->Engine->MaxDatagramLength = This->Mtu;
                // Inform the VPN that the MTU has changed.
                TunnelEvent.Type = TunnelMtuChanged;
                TunnelEvent.MtuChanged.Mtu = This->Mtu;
                This->Engine->EventHandler(&TunnelEvent);
            }
            return QUIC_STATUS_PENDING;
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete [] (uint8_t*) Event->SEND_COMPLETE.ClientContext;
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
        break;
    }
    // TODO:
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ClientAuthStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    QuicLanPeerContext *This = (QuicLanPeerContext*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        if (Event->RECEIVE.BufferCount > 1) {
            printf("Client received %u buffers from Server. Expected 1!\n", Event->RECEIVE.BufferCount);
        }
        QuicLanAuthBlock* AuthBlock = (QuicLanAuthBlock*) Event->RECEIVE.Buffers[0].Buffer;
        if (strnlen(AuthBlock->Pw, AuthBlock->Len) != AuthBlock->Len ||
            AuthBlock->Len != strnlen(This->Engine->Password, sizeof(This->Engine->Password)) ||
            strncmp(AuthBlock->Pw, This->Engine->Password, Event->RECEIVE.Buffers[0].Length - 1)) {
            // Server-provided password doesn't match our password. Kill the connection!
            printf("Server password doesn't match our password! BufferLen: %u, %u != %u, %s != %s\n",
                Event->RECEIVE.Buffers[0].Length,
                AuthBlock->Len,
                strnlen(This->Engine->Password, sizeof(This->Engine->Password)),
                AuthBlock->Pw,
                This->Engine->Password);
            This->State.AuthenticationFailed = true;
            if (This->Engine->RemovePeer(This)) {
                This->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_STATUS_PERMISSION_DENIED);
                This->Engine->MsQuic->ConnectionShutdown(This->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_STATUS_PERMISSION_DENIED);
            }
            // TODO: Indicate to VPN that the last connection has closed, if this is the last.
        } else {
            This->State.Authenticated;

            QuicLanTunnelEvent TunnelEvent{};
            if (This->Mtu < This->Engine->MaxDatagramLength) {
                This->Engine->MaxDatagramLength = This->Mtu;
                TunnelEvent.Type = TunnelMtuChanged;
                TunnelEvent.MtuChanged.Mtu = This->Mtu;
                This->Engine->EventHandler(&TunnelEvent);
            }
            // TODO: this is a hack just for development. Eventually, this will
            // pick an unused IP address based on the info from the control stream.
            TunnelEvent.Type = TunnelIpAddressReady;
            // Client
            TunnelEvent.IpAddressReady.IPv4Addr = "169.254.10.2";
            TunnelEvent.IpAddressReady.IPv6Addr = "[fd71:7569:636c:616e::2]";
            This->Engine->EventHandler(&TunnelEvent);
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        // Delete the send data allocated in ClientAuthenticationStart()
        delete[] (uint8_t*) Event->SEND_COMPLETE.ClientContext;
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
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
    QuicLanPeerContext *This = (QuicLanPeerContext*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
        This->State.ControlStreamClosed = true;
        break;
    }
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
    QuicLanPeerContext *This = (QuicLanPeerContext*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
        This->State.ControlStreamClosed = true;
        break;
    }
    // TODO:
    return QUIC_STATUS_SUCCESS;
}
