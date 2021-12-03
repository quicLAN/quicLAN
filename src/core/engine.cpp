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
    1) authenticates to server
    2) requests ID
    3) requests external IP address
    4) Requests external IP->ID map of rest of swarm.
*/

const QUIC_REGISTRATION_CONFIG RegConfig = { "quiclan", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quiclan-00") - 1, (uint8_t*)"quiclan-00" };
const uint8_t QuicLanIpv6Prefix[] = {0xfd, 0x71, 0x75, 0x69, 0x63, 0x6c, 0x61, 0x6e};
const uint16_t UdpPort = 7490;
const uint64_t IdleTimeoutMs = 30000;
const uint64_t MaxBytesPerKey = 1000000;
const uint8_t DatagramsEnabled = TRUE;
const uint32_t KeepAliveMs = 5000;
const uint16_t BiDiStreamCount = 1;
const uint16_t UniDiStreamCount = 1;

const uint16_t MaxPacketLength = 1500;
const uint32_t WorkItemBatchSize = 10;
const uint32_t MaxDatagramsOutstanding = 50;

void
ConvertIdToAddress(uint16_t Id, QUIC_ADDR& Ip4Addr, QUIC_ADDR& Ip6Addr)
{
    Ip4Addr.Ipv4.sin_addr.s_addr = (Id << 16) + (254u << 8) + 169;
    memcpy(Ip6Addr.Ipv6.sin6_addr.__in6_u.__u6_addr8, QuicLanIpv6Prefix, sizeof(QuicLanIpv6Prefix));
    memset(&Ip6Addr.Ipv6.sin6_addr.__in6_u.__u6_addr8[8], 0, sizeof(in6_addr) - 8);
    Ip6Addr.Ipv6.sin6_addr.__in6_u.__u6_addr16[7] = Id;
}

void
QuicLanEngine::WorkerThreadProc()
{
    std::unique_lock<std::mutex> lock(WorkItemsLock);
    while (true) {
        WorkItemsCv.wait(lock);
        if (ShuttingDown) {
            return;
        }
        if (WorkItems.empty()) {
            continue;
        }
        while (!WorkItems.empty()) {
            if (ShuttingDown) {
                return;
            }
            std::list<QuicLanWorkItem> Batch{};
            auto SpliceEnd = WorkItems.begin();
            for(auto i = 0; SpliceEnd != WorkItems.end() && i < WorkItemBatchSize; ++i, ++SpliceEnd);
            Batch.splice(Batch.end(), WorkItems, WorkItems.begin(), SpliceEnd);
            lock.unlock();

            for (auto& WorkItem : Batch) {
                switch (WorkItem.Type) {
                case AddPeer: {
                    Peers.push_back(WorkItem.AddPeer.Peer);
                    WorkItem.AddPeer.Peer->Inserted = true;
                    break;
                }

                case ControlMessageReceived: {
                    auto Peer = WorkItem.ControlMessage.Peer;
                    auto& RecvData = WorkItem.ControlMessage.RecvData;
                    switch (WorkItem.ControlMessage.Type)
                    {
                    case RequestId: {
                        assert(RecvData.Length == 0);
                        if (Peer->Server) {
                            std::minstd_rand Rng;
                            // TODO: support IPv6 external addresses.
                            Rng.seed(Peer->ExternalAddress.Ipv4.sin_addr.s_addr);
                            bool Generate = true;
                            uint16_t newId = 0;
                            do {
                                // check if it's in the list of known peers, or equal to this id
                                newId = (uint16_t) ((Rng() % 65023u) + 257u);
                                newId = CxPlatByteSwapUint16(newId);
                                if (newId == ID) {
                                    continue;
                                }
                                bool DuplicateId = false;
                                for (auto Peer : Peers) {
                                    if (Peer->ID == newId) {
                                        DuplicateId = true;
                                        break;
                                    }
                                }
                                if (DuplicateId) {
                                    continue;
                                }
                                Generate = false;
                            } while (Generate);
                            printf("Assigning %x ID to client\n", newId);
                            Peer->ID = newId;
                            ConvertIdToAddress(newId, Peer->InternalAddress4, Peer->InternalAddress6);

                            QuicLanMessage* Message = QuicLanMessageAlloc(sizeof(uint16_t));

                            uint8_t* Payload = QuicLanMessageHeaderFormat(AssignId, ID, sizeof(uint16_t), Message->Buffer);

                            memcpy(Payload, &newId, sizeof(newId));

                            QueueWorkItem({.Type = ControlMessageSend, .ControlMessage = {.Peer = Peer, .SendData = Message, .Type = AssignId}});
                        } else {
                            printf("Client received RequestId message!\n");
                            // TODO: kill connection.
                        }
                        break;
                    }

                    case AssignId:
                        if (!Peer->Server) {
                            if (WorkItem.ControlMessage.RecvData.Length != sizeof(uint16_t)) {
                                printf("Client received invalid AssignId message. Length: %u vs. %u\n",
                                WorkItem.ControlMessage.RecvData.Length,
                                sizeof(uint16_t));
                                break;
                            }
                            // ID is in network-order.
                            memcpy(&ID, RecvData.Buffer, sizeof(uint16_t));
                            ConvertIdToAddress(ID, Ip4VpnAddress, Ip6VpnAddress);
                            IdAssigned = true;
                            char Ip4TunnelAddress[INET_ADDRSTRLEN];
                            char Ip6TunnelAddress[INET6_ADDRSTRLEN];

                            QuicLanTunnelEvent TunnelEvent;
                            TunnelEvent.IpAddressReady.IPv4Addr =
                                inet_ntop(AF_INET, &Ip4VpnAddress.Ipv4.sin_addr, Ip4TunnelAddress, sizeof(Ip4TunnelAddress));
                            TunnelEvent.IpAddressReady.IPv6Addr =
                                inet_ntop(AF_INET6, &Ip6VpnAddress.Ipv6.sin6_addr, Ip6TunnelAddress, sizeof(Ip6TunnelAddress));
                            TunnelEvent.Type = TunnelIpAddressReady;
                            EventHandler(&TunnelEvent);
                        } else {
                            printf("Server received AssignId message!\n");
                            // TODO: Kill connection.
                        }
                        break;

                    default:
                        break;
                    }

                    if (WorkItem.ControlMessage.RecvData.Length > 0) {
                        delete[] WorkItem.ControlMessage.RecvData.Buffer;
                    }

                    break;
                }

                case ControlMessageSend: {
                    switch (WorkItem.ControlMessage.Type) {
                    case RequestId: {
                        QuicLanMessage* Message = QuicLanMessageAlloc(0);
                        QuicLanMessageHeaderFormat(RequestId, ID, 0, Message->Buffer);

                        HQUIC Stream = nullptr;
                        if (QUIC_FAILED(MsQuic->StreamOpen(
                                WorkItem.ControlMessage.Peer->Connection,
                                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                                SendControlStreamCallback,
                                WorkItem.ControlMessage.Peer,
                                &Stream)) ||
                            QUIC_FAILED(MsQuic->StreamSend(
                                Stream,
                                &Message->QuicBuffer, 1,
                                QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN,
                                Message))) {
                            printf("Client failed to send requestId message! \n");
                            QuicLanMessageFree(Message);
                            if (Stream != nullptr) {
                                MsQuic->StreamClose(Stream);
                            }
                        } else {
                            // TODO: Create retry logic
                            IdRequested = true;
                        }
                        break;
                    }

                    case AssignId: {
                        auto Message = WorkItem.ControlMessage.SendData;
                        auto Peer = WorkItem.ControlMessage.Peer;
                        HQUIC Stream = nullptr;
                        if (QUIC_FAILED(MsQuic->StreamOpen(
                                Peer->Connection,
                                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                                SendControlStreamCallback,
                                Peer,
                                &Stream)) ||
                            QUIC_FAILED(MsQuic->StreamSend(
                                Stream,
                                &Message->QuicBuffer, 1,
                                QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN,
                                Message))) {
                            printf("Server failed to send AssignId message to client.\n");
                            QuicLanMessageFree(Message);
                            if (Stream != nullptr) {
                                MsQuic->StreamClose(Stream);
                            }
                        }
                        break;
                    }

                    default:
                        printf("Unimplemented ControlMessageSend type %d\n", WorkItem.ControlMessage.Type);
                        break;
                    }
                    break;
                }

                case MtuChanged: {
                    if (WorkItem.MtuChanged.Peer != nullptr) {
                        WorkItem.MtuChanged.Peer->Mtu = WorkItem.MtuChanged.NewMtu;
                    }
                    uint16_t MinMtu = MaxPacketLength;
                    for (auto& Peer : Peers) {
                        if (Peer->Mtu < MinMtu && Peer->Mtu > 0) {
                            MinMtu = Peer->Mtu;
                        }
                    }
                    if (MinMtu != MaxDatagramLength) {
                        MaxDatagramLength = MinMtu;
                        // Inform the VPN that the MTU has changed.
                        QuicLanTunnelEvent TunnelEvent;
                        TunnelEvent.Type = TunnelMtuChanged;
                        TunnelEvent.MtuChanged.Mtu = MaxDatagramLength;
                        EventHandler(&TunnelEvent);
                    }
                    break;
                }

                case ReceivePacket: {
                    QuicLanTunnelEvent TunnelEvent;
                    TunnelEvent.Type = TunnelPacketReceived;
                    TunnelEvent.PacketReceived.Packet = WorkItem.RecvPacket.Packet.Buffer;
                    TunnelEvent.PacketReceived.PacketLength = WorkItem.RecvPacket.Packet.Length;
                    EventHandler(&TunnelEvent);
                    delete[] WorkItem.RecvPacket.Packet.Buffer; // TODO: return to lookaside list.
                    break;
                }

                case RemovePeer: {
                    auto Peer = WorkItem.RemovePeer.Peer;
                    auto it = Peers.begin();
                    while(*it != Peer) it++;
                    if (it != Peers.end()) {
                        Peers.erase(it);
                        Peer->Inserted = false;
                    }
                    if (WorkItem.RemovePeer.ShutdownPeer) {
                        MsQuic->ConnectionShutdown(Peer->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, WorkItem.RemovePeer.ShutdownError);
                    }
                    if (Peers.size() == 0) {
                        QuicLanTunnelEvent Event;
                        Event.Type = TunnelDisconnected;
                        EventHandler(&Event);
                    }
                    break;
                }

                case SendPacket: {
                    QuicLanPeerContext* FoundPeer = nullptr;
                    auto SendBuffer = WorkItem.SendPacket.Packet;
                    struct ip* Ip4Header = nullptr;
                    struct ip6_hdr* Ip6Header = nullptr;
                    if ((SendBuffer->Buffer[0] & 0xF0) >> 4 == 4) {
                        Ip4Header = (struct ip*) SendBuffer->Buffer;
                        for (auto Peer : Peers) {
                            if (memcmp(&Peer->InternalAddress4.Ipv4.sin_addr, &Ip4Header->ip_dst, sizeof(in_addr)) == 0) {
                                FoundPeer = Peer;
                                break;
                            }
                        }
                    } else {
                        assert((SendBuffer->Buffer[0] & 0xF0) >> 4 == 6);
                        Ip6Header = (struct ip6_hdr*) SendBuffer->Buffer;
                        for (auto Peer : Peers) {
                            if (memcmp(&Peer->InternalAddress6.Ipv6.sin6_addr, &Ip6Header->ip6_dst, sizeof(in6_addr)) == 0) {
                                FoundPeer = Peer;
                                break;
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
                        if (QUIC_FAILED(Status)) {
                            printf("DatagramSend failed! %u\n", Status);
                            delete SendBuffer;
                        } else {
                            IncrementOutstandingDatagrams();
                        }
                    } else {
                        printf("Failed to find peer!\n");
                        delete SendBuffer;
                    }
                    break;
                }

                case Shutdown: {
                    std::unique_lock Lock(StopLock);
                    MsQuic->ListenerStop(Listener);
                    // TODO: Inform all peers of the disconnect
                    ShuttingDown = true;
                    for (auto Peer : Peers) {
                        Peer->State.Disconnecting = true;
                        Peer->Inserted = false;
                        MsQuic->ConnectionShutdown(
                            Peer->Connection,
                            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                            0);
                    }
                    Peers.clear();
                    StopLock.unlock();
                    StopCv.notify_one();
                    break;
                }

                default:
                    printf("Unimplemented WorkItem type %d\n", WorkItem.Type);
                    break;
                }
            }

            // Lock must be held at the end of the loop
            lock.lock();
        }
    }
}

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

    try {
        WorkerThread = std::thread(QuicLanEngine::WorkerThreadProc, this);
    } catch (...) {
        printf("Failed to create worker thread!\n");
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
    // Poke worker thread to exit.
    QueueWorkItem({});
    WorkerThread.join();
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
    Settings.PeerUnidiStreamCount = UniDiStreamCount;
    Settings.IsSet.PeerUnidiStreamCount = true;

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

    Peer = new QuicLanPeerContext{};
    Peer->Engine = this;
    Peer->FirstConnection = true;
    // TODO: Hacks for development. Remove when implementing address announcements
    Peer->ID = 1;
    ConvertIdToAddress(Peer->ID, Peer->InternalAddress4, Peer->InternalAddress6);
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
    if (!QueueWorkItem({.Type = AddPeer, .AddPeer = {Peer}})) {
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
        ID = 1;
        IdAssigned = true;
        ConvertIdToAddress(ID, Ip4VpnAddress, Ip6VpnAddress);
        char VpnAddress4[INET_ADDRSTRLEN];
        char VpnAddress6[INET6_ADDRSTRLEN];
        QuicLanTunnelEvent TunnelEvent{};
        TunnelEvent.Type = TunnelIpAddressReady;
        TunnelEvent.IpAddressReady.IPv4Addr =
            inet_ntop(AF_INET, &Ip4VpnAddress.Ipv4.sin_addr, VpnAddress4, sizeof(VpnAddress4));
        TunnelEvent.IpAddressReady.IPv6Addr =
            inet_ntop(AF_INET6, &Ip6VpnAddress.Ipv6.sin6_addr, VpnAddress6, sizeof(VpnAddress6));
        EventHandler(&TunnelEvent);
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
    PeerContext->State.Authenticating = true;
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
    return QueueWorkItem({.Type = SendPacket, .SendPacket = {.Packet = SendBuffer}});
}

bool
QuicLanEngine::Stop()
{
    bool result = QueueWorkItem({.Type = Shutdown});
    std::unique_lock Lock(StopLock);
    StopCv.wait(Lock);
    return result;
}

bool
QuicLanEngine::QueueWorkItem(
    _In_ const QuicLanWorkItem& WorkItem)
{
    std::unique_lock<std::mutex> Lock(WorkItemsLock);
    WorkItems.emplace_back(WorkItem);
    Lock.unlock();
    WorkItemsCv.notify_one();
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
        QuicLanPeerContext* PeerContext = new QuicLanPeerContext{};
        PeerContext->ExternalAddress = *Event->NEW_CONNECTION.Info->RemoteAddress;
        PeerContext->Connection = Event->NEW_CONNECTION.Connection;
        PeerContext->Server = true;
        PeerContext->Engine = This;
        if (This->QueueWorkItem({.Type = AddPeer, .AddPeer = {PeerContext}})) { // TODO: Wait to add peer until connection/authentication succeeds.
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
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        This->State.Disconnected = true;
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        if (!This->State.Authenticated && (Event->STREAMS_AVAILABLE.BidirectionalCount + Event->STREAMS_AVAILABLE.UnidirectionalCount > 0)) {
            printf(
                "Client allowed %u BiDi and %u Unidi streams before server authenticated!\n",
                Event->STREAMS_AVAILABLE.BidirectionalCount,
                Event->STREAMS_AVAILABLE.UnidirectionalCount);
        }
        if (This->FirstConnection && !This->Engine->IdAssigned && !This->Engine->IdRequested) {
            // Start client by requesting IP address.
            QuicLanWorkItem WorkItem;
            WorkItem.Type = ControlMessageSend;
            WorkItem.ControlMessage.Type = RequestId;
            WorkItem.ControlMessage.Peer = This;
            This->Engine->QueueWorkItem(WorkItem);
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        if (!This->State.Authenticated && !This->State.Authenticating) {
            This->Engine->ClientAuthenticationStart(Event->PEER_STREAM_STARTED.Stream, This);
        } else if (This->State.Authenticated) {
            QuicLanControlStreamReceiveContext* RecvCtx = new(std::nothrow) QuicLanControlStreamReceiveContext();
            RecvCtx->Peer = This;
            This->Engine->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QuicLanEngine::ReceiveControlStreamCallback, RecvCtx);
        } else {
            printf("Client received stream start from server during authentication!\n");
            assert(false);
        }
        break;
    }
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // Take the datagram and send it over loopback to the VPN interface.
        // TODO: Check flags and if FIN flag set, close connection?
        QuicLanWorkItem WorkItem;
        WorkItem.Type = ReceivePacket;
        WorkItem.RecvPacket.Packet.Buffer = new(std::nothrow) uint8_t[Event->DATAGRAM_RECEIVED.Buffer->Length];
        if (WorkItem.RecvPacket.Packet.Buffer == nullptr) {
            printf("Failed to allocate %u bytes for received packet!\n", Event->DATAGRAM_RECEIVED.Buffer->Length);
            break;
        }
        WorkItem.RecvPacket.Packet.Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
        memcpy(WorkItem.RecvPacket.Packet.Buffer, Event->DATAGRAM_RECEIVED.Buffer->Buffer, WorkItem.RecvPacket.Packet.Length);
        This->Engine->QueueWorkItem(WorkItem);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
            This->Mtu = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
            This->Engine->QueueWorkItem({.Type = MtuChanged});
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED) {
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
        This->State.Connected = true;
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
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        This->State.Disconnected = true;
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        // TODO: kill connection; peer tried to start control stream before authenticating.
        printf("Client tried to start stream before authenticating!!\n");
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
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n",
            Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, 0, false}});
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        This->State.Disconnected = true;
        if (!This->Inserted) {
            This->Engine->MsQuic->ConnectionClose(Connection);
            delete This;
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        This->ExternalAddress = *Event->PEER_ADDRESS_CHANGED.Address; // TODO move this to worker thread.
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        if (This->State.Authenticated) {
            QuicLanControlStreamReceiveContext* RecvCtx = new(std::nothrow) QuicLanControlStreamReceiveContext();
            RecvCtx->Peer = This;
            This->Engine->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QuicLanEngine::ReceiveControlStreamCallback, RecvCtx);
        } else {
            // TODO: kill connection; peer tried to start control stream before authenticating.
            printf("Client tried to start stream while not yet authenticated (but this is authenticated callback?)\n");
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        // Check that the packet is destined for this server, and send it to
        /// the VPN interface.
        // If not destined for this server, forward to the correct peer.
        // TODO: Check flags and if FIN flag set, close connection?
        QuicLanWorkItem WorkItem;
        WorkItem.Type = ReceivePacket;
        WorkItem.RecvPacket.Packet.Buffer = new(std::nothrow) uint8_t[Event->DATAGRAM_RECEIVED.Buffer->Length];
        if (WorkItem.RecvPacket.Packet.Buffer == nullptr) {
            printf("Failed to allocate %u bytes for received packet!\n", Event->DATAGRAM_RECEIVED.Buffer->Length);
            break;
        }
        WorkItem.RecvPacket.Packet.Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
        memcpy(WorkItem.RecvPacket.Packet.Buffer, Event->DATAGRAM_RECEIVED.Buffer->Buffer, WorkItem.RecvPacket.Packet.Length);
        This->Engine->QueueWorkItem(WorkItem);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        if (Event->DATAGRAM_STATE_CHANGED.SendEnabled && This->Mtu != Event->DATAGRAM_STATE_CHANGED.MaxSendLength) {
            This->Engine->QueueWorkItem({.Type = MtuChanged, .MtuChanged = {.Peer = This, .NewMtu = Event->DATAGRAM_STATE_CHANGED.MaxSendLength}});
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED) {
            This->Engine->DecrementOutstandingDatagrams();
            uint8_t* Buffer = (uint8_t*) Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
            delete [] Buffer; // TODO: add buffer to lookaside list
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
        This->State.Authenticating = true;
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
            This->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_STATUS_CONNECTION_REFUSED);
            This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, QUIC_STATUS_CONNECTION_REFUSED, true}});
        } else {
            // Client-provided password matches! Send our password in response and allow client to open control stream.
            This->State.Authenticated = true;
            QUIC_BUFFER* SendBuffer = new QUIC_BUFFER;
            SendBuffer->Length = Event->RECEIVE.Buffers[0].Length;
            SendBuffer->Buffer = Event->RECEIVE.Buffers[0].Buffer;
            Event->RECEIVE.TotalBufferLength = 0; // Tell MsQuic to not free the receive buffer yet.
            QUIC_SETTINGS Settings{};
            Settings.PeerUnidiStreamCount = UniDiStreamCount;
            Settings.IsSet.PeerUnidiStreamCount = true;

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
                This->Engine->QueueWorkItem({.Type = MtuChanged});
            }
            return QUIC_STATUS_PENDING; // Tell MsQuic to not free the receive buffer yet.
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        This->Engine->MsQuic->StreamReceiveComplete(Stream, ((QUIC_BUFFER*) Event->SEND_COMPLETE.ClientContext)->Length);
        delete (QUIC_BUFFER*) Event->SEND_COMPLETE.ClientContext;
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
        printf("Server auth stream closed\n");
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
            This->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_STATUS_CONNECTION_REFUSED);
            This->Engine->QueueWorkItem({.Type = QuicLanWorkItemType::RemovePeer, .RemovePeer = {This, QUIC_STATUS_CONNECTION_REFUSED, true}});
        } else {
            This->State.Authenticated = true;

            QuicLanTunnelEvent TunnelEvent{};
            if (This->Mtu < This->Engine->MaxDatagramLength) {
                This->Engine->QueueWorkItem({.Type = MtuChanged});
            }
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        // Delete the send data allocated in ClientAuthenticationStart()
        delete[] (uint8_t*) Event->SEND_COMPLETE.ClientContext;
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        This->Engine->MsQuic->StreamClose(Stream);
        printf("Client auth stream closed\n");
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::SendControlStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            printf("[Strm] %p started with %d\n", Stream, Event->START_COMPLETE.Status);
            if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
                printf("Failed to start control stream! %u\n", Event->START_COMPLETE.Status);
                // TODO: shutdown the connection.
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            QuicLanMessageFree((QuicLanMessage*)Event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[Strm] %p shutdown complete.\n", Stream);
            ((QuicLanPeerContext*)Context)->Engine->MsQuic->StreamClose(Stream);
            break;
        default:
            //printf("[Strm] %p Received Event %d, unhandled\n", Stream, Event->Type);
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicLanEngine::ReceiveControlStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event)
{
    QuicLanControlStreamReceiveContext* RecvCtx = (QuicLanControlStreamReceiveContext*)Context;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            if (RecvCtx->Offset == 0) {
                // First receive on the stream.
                assert(Event->RECEIVE.AbsoluteOffset == 0);
                if (Event->RECEIVE.TotalBufferLength < sizeof(QuicLanMessageHeader)) {
                    printf("Received data is not enough for the message header(%llu)\n", Event->RECEIVE.TotalBufferLength);
                    // TODO: kill connection
                } else if (Event->RECEIVE.Buffers[0].Length < sizeof(QuicLanMessageHeader)) {
                    if (Event->RECEIVE.BufferCount < 2 || Event->RECEIVE.Buffers[1].Length < sizeof(QuicLanMessageHeader) - Event->RECEIVE.Buffers[0].Length) {
                        printf("Received data is split and not enough for message header(%llu)\n", Event->RECEIVE.TotalBufferLength);
                        // TODO: kill connection
                    }
                    QuicLanMessageHeader TempHeader;
                    auto Remainder = sizeof(QuicLanMessageHeader) - Event->RECEIVE.Buffers[0].Length;
                    memcpy(&TempHeader, Event->RECEIVE.Buffers[0].Buffer, Event->RECEIVE.Buffers[0].Length);
                    memcpy(
                        ((uint8_t*)&TempHeader) + Event->RECEIVE.Buffers[0].Length,
                        Event->RECEIVE.Buffers[1].Buffer,
                        Remainder);
                    uint32_t Offset = 0;
                    uint32_t Length = 0;
                    if (!QuicLanMessageHeaderParse((uint8_t*)&TempHeader, Offset, RecvCtx->Type, RecvCtx->HostId, Length)) {
                        printf("Header failed to parse!\n");
                        // TODO: kill connection
                    }
                    if (Length > 0) {
                        RecvCtx->Data.Buffer = new(std::nothrow) uint8_t[Length];
                        if (RecvCtx->Data.Buffer == nullptr) {
                            printf("Failed to allocate receive buffer for %u!\n", Length);
                            RecvCtx->Peer->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, QUIC_STATUS_OUT_OF_MEMORY);
                            break;
                        }
                        RecvCtx->Data.Length = Length;
                        auto CopyLength = (Length > (Event->RECEIVE.Buffers[1].Length - Remainder)) ? (Event->RECEIVE.Buffers[1].Length - Remainder) : Length;
                        memcpy(RecvCtx->Data.Buffer, Event->RECEIVE.Buffers[1].Buffer + Remainder, CopyLength);
                        RecvCtx->Offset += CopyLength;
                    }
                } else {
                    uint32_t Offset = 0;
                    uint32_t Length = 0;
                    if (!QuicLanMessageHeaderParse(Event->RECEIVE.Buffers[0].Buffer, Offset, RecvCtx->Type, RecvCtx->HostId, Length)) {
                        printf("Header failed to parse!\n");
                        // TODO: kill connection
                    }
                    if (Length > 0) {
                        RecvCtx->Data.Buffer = new(std::nothrow) uint8_t[Length];
                        if (RecvCtx->Data.Buffer == nullptr) {
                            printf("Failed to allocate receive buffer for %u!\n", Length);
                            RecvCtx->Peer->Engine->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, QUIC_STATUS_OUT_OF_MEMORY);
                            break;
                        }
                        RecvCtx->Data.Length = Length;
                        for (auto i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                            auto CopyLength = (Length > (Event->RECEIVE.Buffers[i].Length - Offset)) ? (Event->RECEIVE.Buffers[i].Length - Offset) : Length;
                            memcpy(RecvCtx->Data.Buffer + RecvCtx->Offset, Event->RECEIVE.Buffers[i].Buffer + Offset, CopyLength);
                            Offset = 0;
                            RecvCtx->Offset += CopyLength;
                            Length -= CopyLength;
                        }
                    }
                }
            } else {
                // Receive more data after the first event.
                for (auto i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                    memcpy(RecvCtx->Data.Buffer + RecvCtx->Offset, Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
                    RecvCtx->Offset += Event->RECEIVE.Buffers[i].Length;
                }
            }
            if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                // All control data received, validate no data was lost.
                if (RecvCtx->Offset != RecvCtx->Data.Length) {
                    printf("Not all data was written to buffer! Offset: %u vs. Length: %u\n", RecvCtx->Offset, RecvCtx->Data.Length);
                }
                if (RecvCtx->Offset != (Event->RECEIVE.AbsoluteOffset + Event->RECEIVE.TotalBufferLength) - sizeof(QuicLanMessageHeader)) {
                    printf(
                        "Not all data written to buffer! Offset: %u, AbsoluteOffset: %u, TotalBufferLen: %u\n",
                        RecvCtx->Offset,
                        Event->RECEIVE.AbsoluteOffset,
                        Event->RECEIVE.TotalBufferLength);
                }
                RecvCtx->Peer->Engine->QueueWorkItem({
                    .Type = ControlMessageReceived,
                    .ControlMessage = {
                        .Peer = RecvCtx->Peer,
                        .RecvData = RecvCtx->Data,
                        .Type = RecvCtx->Type}});
                RecvCtx->Data = {0, nullptr};
            }
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            printf("[Strm] %p shutdown complete.\n", Stream);
            auto StreamClose = RecvCtx->Peer->Engine->MsQuic->StreamClose;
            if (RecvCtx->Data.Buffer != nullptr) {
                delete [] RecvCtx->Data.Buffer;
                RecvCtx->Data.Buffer = nullptr;
            }
            delete RecvCtx;
            StreamClose(Stream);
            break;
        }
        default:
            //printf("[Strm] %p Received Event %d, unhandled\n", Stream, Event->Type);
            break;
    }
    return QUIC_STATUS_SUCCESS;
}
