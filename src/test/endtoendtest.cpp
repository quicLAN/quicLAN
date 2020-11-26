/*
    Licensed under the MIT License.
*/
#include "tests.h"

const char* TestPassword = "TestPassword";

std::string ServerEnginev4Address;
std::string ServerEnginev6Address;
std::string ClientEnginev4Address;
std::string ClientEnginev6Address;
uint16_t ServerEngineMtu = 0;
uint16_t ClientEngineMtu = 0;
bool ServerEngineReceivedData = false;
bool ClientEngineReceivedData = false;

std::mutex ServerEngineMutex;
std::mutex ClientEngineMutex;

std::condition_variable ServerEngineCv;
std::condition_variable ClientEngineCv;

void
BasicConnectionListener1(QuicLanTunnelEvent* Event)
{
    switch (Event->Type) {
    case TunnelIpAddressReady: {
        std::unique_lock lk(ServerEngineMutex);
        ServerEnginev4Address = Event->IpAddressReady.IPv4Addr;
        ServerEnginev6Address = Event->IpAddressReady.IPv6Addr;
        lk.unlock();
        ServerEngineCv.notify_all();
        break;
    }
    case TunnelMtuChanged:
        ServerEngineMtu = Event->MtuChanged.Mtu;
        break;
    case TunnelPacketReceived: {
        std::unique_lock lk(ServerEngineMutex);
        ServerEngineReceivedData = true;
        lk.unlock();
        ServerEngineCv.notify_all();
        break;
    }
    default:
        break;
    }
}

void
BasicConnectionListener2(QuicLanTunnelEvent* Event)
{
    switch (Event->Type) {
    case TunnelIpAddressReady: {
        std::unique_lock lk(ClientEngineMutex);
        ClientEnginev4Address = Event->IpAddressReady.IPv4Addr;
        ClientEnginev6Address = Event->IpAddressReady.IPv6Addr;
        lk.unlock();
        ClientEngineCv.notify_all();
        break;
    }
    case TunnelMtuChanged:
        ClientEngineMtu = Event->MtuChanged.Mtu;
        break;
    case TunnelPacketReceived: {
        std::unique_lock lk(ClientEngineMutex);
        ClientEngineReceivedData = true;
        lk.unlock();
        ClientEngineCv.notify_all();
        break;
    }
    default:
        break;
    }
}

inline
void
PopulateHeader(
    struct ip* Header,
    const char* Source,
    const char* Dest,
    uint16_t Length)
{
    Header->ip_v = 4;
    inet_aton(Source, &Header->ip_src);
    inet_aton(Dest, &Header->ip_dst);
    Header->ip_len = htons(Length);
}

bool
TestBasicConnection()
{
    bool Result = true;
    QuicLanEngine* ServerEngine = nullptr;
    QuicLanEngine* ClientEngine = nullptr;
    QuicLanPacket* ServerEnginePacket = nullptr;
    QuicLanPacket* ClientEnginePacket = nullptr;

    if (!InitializeQuicLanEngine(TestPassword, BasicConnectionListener1, &ServerEngine)) {
        Result = false;
        printf("Failed initializing ServerEngine\n");
        goto Cleanup;
    }

    if (!InitializeQuicLanEngine(TestPassword, BasicConnectionListener2, &ClientEngine)) {
        Result = false;
        printf("Failed initializing ClientEngine\n");
        goto Cleanup;
    }

    if (!AddServer(ClientEngine, "127.0.0.1", DEFAULT_QUICLAN_SERVER_PORT)) {
        Result = false;
        printf("Failed adding server to ClientEngine\n");
        goto Cleanup;
    }

    if (!Start(ServerEngine, DEFAULT_QUICLAN_SERVER_PORT)) {
        Result = false;
        printf("Failed starting ServerEngine\n");
        goto Cleanup;
    }

    if (!Start(ClientEngine, DEFAULT_QUICLAN_SERVER_PORT+1)) {
        Result = false;
        printf("Failed starting ClientEngine\n");
        goto Cleanup;
    }

    {
        // Wait for ServerEngine to get an IP address
        std::unique_lock lk(ServerEngineMutex);
        ServerEngineCv.wait(lk, []{return ServerEnginev4Address.length() > 0;});
        printf("ServerEngine IP4 Address %s\n", ServerEnginev4Address.c_str());
        printf("ServerEngine IP6 Address %s\n", ServerEnginev6Address.c_str());
    }
    {
        // Wait for ClientEngine to get an IP address
        std::unique_lock lk(ClientEngineMutex);
        ClientEngineCv.wait(lk, []{return ClientEnginev4Address.length() > 0;});
        printf("ClientEngine IP4 address %s\n", ClientEnginev4Address.c_str());
        printf("ClientEngine IP6 address %s\n", ClientEnginev6Address.c_str());
    }

    ServerEnginePacket = RequestPacket(ServerEngine);
    ClientEnginePacket = RequestPacket(ClientEngine);

    // Populate packets with valid IPv4 header matching destination IP address
    PopulateHeader(
        (struct ip*) ServerEnginePacket->Buffer,
        ServerEnginev4Address.c_str(),
        ClientEnginev4Address.c_str(),
        ServerEngineMtu);

    PopulateHeader(
        (struct ip*) ClientEnginePacket->Buffer,
        ClientEnginev4Address.c_str(),
        ServerEnginev4Address.c_str(),
        ClientEngineMtu);

    if (!Send(ServerEngine, ServerEnginePacket)) {
        Result = false;
        printf("Failed sending ServerEngine! ServerEngineMtu: %u\n",ServerEngineMtu);
        goto Cleanup;
    }
    if (!Send(ClientEngine, ClientEnginePacket)) {
        Result = false;
        printf("Failed sending ClientEngine! ClientEngineMtu: %u\n", ClientEngineMtu);
        goto Cleanup;
    }

    {
        // Wait for ServerEngine to get a packet
        std::unique_lock lk(ServerEngineMutex);
        ServerEngineCv.wait(lk, []{return ServerEngineReceivedData;});
    }
    {
        // Wait for ClientEngine to get a packet
        std::unique_lock lk(ClientEngineMutex);
        ClientEngineCv.wait(lk, []{return ClientEngineReceivedData;});
    }

    assert(ServerEngineReceivedData);
    assert(ClientEngineReceivedData);

    printf("Packets received and test passed!\n");

    if (!Stop(ServerEngine)) {
        Result = false;
        printf("Failed stopping ServerEngine\n");
    }
    if (!Stop(ClientEngine)) {
        Result = false;
        printf("Failed stopping ClientEngine\n");
    }

Cleanup:
    UninitializeQuicLanEngine(ServerEngine);
    UninitializeQuicLanEngine(ClientEngine);

    return Result;
}
