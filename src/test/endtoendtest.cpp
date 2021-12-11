/*
    Licensed under the MIT License.
*/
#include "tests.h"


struct EngineScope {
    QuicLanEngine* Handle;
    EngineScope() noexcept : Handle(nullptr) { }
    EngineScope(QuicLanEngine* handle) noexcept : Handle(handle) { }
    ~EngineScope() noexcept { if (Handle) { UninitializeQuicLanEngine(Handle); } }
    operator QuicLanEngine*() const noexcept { return Handle; }
};

const char* TestPassword = "TestPassword";
const char* BadPassword = "BadPassword";

struct BasicConnectionTestContext {

    BasicConnectionTestContext() = default;

    BasicConnectionTestContext(const char* const ClientPass, const char* const ServerPass)
        : ClientPassword(ClientPass), ServerPassword(ServerPass) {}

    ~BasicConnectionTestContext() = default;

    std::string ServerEnginev4Address;
    std::string ServerEnginev6Address;
    std::string ClientEnginev4Address;
    std::string ClientEnginev6Address;

    std::string ServerPassword;
    std::string ClientPassword;

    uint16_t ServerEngineMtu = 0;
    uint16_t ClientEngineMtu = 0;
    bool ServerEngineReceivedData = false;
    bool ClientEngineReceivedData = false;

    bool ClientDisconnected = false;

    std::mutex ServerEngineMutex;
    std::mutex ClientEngineMutex;

    std::condition_variable ServerEngineCv;
    std::condition_variable ClientEngineCv;

    bool ExpectConnectionFail = false;

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

    static
    void ServerHandler(QuicLanTunnelEvent* Event, void* Context)
    {
        auto This = (BasicConnectionTestContext*)Context;
        switch (Event->Type) {
        case TunnelIpAddressReady: {
            std::unique_lock lk(This->ServerEngineMutex);
            This->ServerEnginev4Address = Event->IpAddressReady.IPv4Addr;
            This->ServerEnginev6Address = Event->IpAddressReady.IPv6Addr;
            lk.unlock();
            This->ServerEngineCv.notify_all();
            break;
        }
        case TunnelMtuChanged:
            This->ServerEngineMtu = Event->MtuChanged.Mtu;
            break;
        case TunnelPacketReceived: {
            std::unique_lock lk(This->ServerEngineMutex);
            This->ServerEngineReceivedData = true;
            lk.unlock();
            This->ServerEngineCv.notify_all();
            break;
        }
        default:
            break;
        }
    };

    static
    void ClientHandler(QuicLanTunnelEvent* Event, void* Context)
    {
        auto This = (BasicConnectionTestContext*)Context;
        switch (Event->Type) {
        case TunnelIpAddressReady: {
            std::unique_lock lk(This->ClientEngineMutex);
            This->ClientEnginev4Address = Event->IpAddressReady.IPv4Addr;
            This->ClientEnginev6Address = Event->IpAddressReady.IPv6Addr;
            lk.unlock();
            This->ClientEngineCv.notify_all();
            break;
        }
        case TunnelMtuChanged:
            This->ClientEngineMtu = Event->MtuChanged.Mtu;
            break;
        case TunnelPacketReceived: {
            std::unique_lock lk(This->ClientEngineMutex);
            This->ClientEngineReceivedData = true;
            lk.unlock();
            This->ClientEngineCv.notify_all();
            break;
        }
        case TunnelDisconnected: {
            std::unique_lock lk(This->ClientEngineMutex);
            This->ClientDisconnected = true;
            lk.unlock();
            This->ClientEngineCv.notify_all();
            break;
        }
        default:
            break;
        }
    };

    void
    Run()
    {
        QuicLanEngine* ServerEngine = nullptr;
        QuicLanEngine* ClientEngine = nullptr;
        QuicLanPacket* ServerEnginePacket = nullptr;
        QuicLanPacket* ClientEnginePacket = nullptr;

        ASSERT_TRUE(InitializeQuicLanEngine(ServerPassword.c_str(), ServerHandler, this, &ServerEngine));
        EngineScope ServerScope(ServerEngine);

        ASSERT_TRUE(InitializeQuicLanEngine(ClientPassword.c_str(), ClientHandler, this, &ClientEngine));
        EngineScope ClientScope(ClientEngine);

        ASSERT_TRUE(AddServer(ClientEngine, "127.0.0.1", DEFAULT_QUICLAN_SERVER_PORT));

        ASSERT_TRUE(Start(ServerEngine, DEFAULT_QUICLAN_SERVER_PORT));

        ASSERT_TRUE(Start(ClientEngine, DEFAULT_QUICLAN_SERVER_PORT+1));

        if (ExpectConnectionFail) {
            std::unique_lock lk(ClientEngineMutex);
            ClientEngineCv.wait(lk, [this]{return ClientDisconnected;});
            ASSERT_TRUE(Stop(ClientEngine));
            ASSERT_TRUE(Stop(ServerEngine));
            return;
        }

        {
            // Wait for ServerEngine to get an IP address
            std::unique_lock lk(ServerEngineMutex);
            ServerEngineCv.wait(lk, [this]{return ServerEnginev4Address.length() > 0;});
            // printf("ServerEngine IP4 Address %s\n", ServerEnginev4Address.c_str());
            // printf("ServerEngine IP6 Address %s\n", ServerEnginev6Address.c_str());
        }
        {
            // Wait for ClientEngine to get an IP address
            std::unique_lock lk(ClientEngineMutex);
            ClientEngineCv.wait(lk, [this]{return ClientEnginev4Address.length() > 0;});
            // printf("ClientEngine IP4 address %s\n", ClientEnginev4Address.c_str());
            // printf("ClientEngine IP6 address %s\n", ClientEnginev6Address.c_str());
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

        ASSERT_TRUE(Send(ServerEngine, ServerEnginePacket));
        ASSERT_TRUE(Send(ClientEngine, ClientEnginePacket));

        {
            // Wait for ServerEngine to get a packet
            std::unique_lock lk(ServerEngineMutex);
            ServerEngineCv.wait(lk, [this]{return ServerEngineReceivedData;});
        }
        {
            // Wait for ClientEngine to get a packet
            std::unique_lock lk(ClientEngineMutex);
            ClientEngineCv.wait(lk, [this]{return ClientEngineReceivedData;});
        }

        ASSERT_TRUE(ServerEngineReceivedData);
        ASSERT_TRUE(ClientEngineReceivedData);

        // printf("Packets received and test passed!\n");

        ASSERT_TRUE(Stop(ServerEngine));
        ASSERT_TRUE(Stop(ClientEngine));
    }
};

/*
    A basic test that just starts a client and server and connects and send a datagram packet through.
*/
TEST(E2E, TestBasicConnection)
{
    BasicConnectionTestContext Conn(TestPassword, TestPassword);
    Conn.Run();
}

TEST(E2E, TestBasicConnectionBadPassword)
{
    BasicConnectionTestContext Conn(BadPassword, TestPassword);
    Conn.ExpectConnectionFail = true;
    Conn.Run();
}
