/*
    Licensed under the MIT License.
*/
#include "tests.h"


struct EngineScope {
    QuicLanEngine* Handle;
    EngineScope() noexcept : Handle(nullptr) { }
    EngineScope(QuicLanEngine* handle) noexcept : Handle(handle) { }
    ~EngineScope() noexcept { reset(); }
    operator QuicLanEngine*() const noexcept { return Handle; }
    QuicLanEngine** operator&() noexcept {reset(); return &Handle; }
    void reset(QuicLanEngine* Engine = nullptr) {if (Handle) UninitializeQuicLanEngine(Handle); Handle = Engine; }
};

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

const char* const TestPassword = "TestPassword";
const char* const BadPassword = "BadPassword";

struct TestEngine {
    EngineScope Engine;
    std::string v4Address;
    std::string v6Address;

    std::string Password;

    uint16_t Mtu = 0;
    bool ReceivedData = false;

    bool Disconnected = false;

    std::mutex EngineMutex;
    std::condition_variable EngineCv;

    bool ExpectConnectionFail = false;

    static
    void Handler(QuicLanTunnelEvent* Event, void* Context)
    {
        auto This = (TestEngine*)Context;
        switch (Event->Type) {
        case TunnelIpAddressReady: {
            std::unique_lock lk(This->EngineMutex);
            This->v4Address = Event->IpAddressReady.IPv4Addr;
            This->v6Address = Event->IpAddressReady.IPv6Addr;
            lk.unlock();
            This->EngineCv.notify_all();
            break;
        }
        case TunnelMtuChanged:
            This->Mtu = Event->MtuChanged.Mtu;
            break;
        case TunnelPacketReceived: {
            std::unique_lock lk(This->EngineMutex);
            This->ReceivedData = true;
            lk.unlock();
            This->EngineCv.notify_all();
            break;
        }
        case TunnelDisconnected: {
            std::unique_lock lk(This->EngineMutex);
            This->Disconnected = true;
            lk.unlock();
            This->EngineCv.notify_all();
            break;
        }
        default:
            break;
        }
    };

    void
    Initialize() {
        ASSERT_TRUE(InitializeQuicLanEngine(Password.c_str(), Handler, this, &Engine));
    }

    void
    AddServer(const char* const Address, uint16_t Port = DEFAULT_QUICLAN_SERVER_PORT) {
        ASSERT_TRUE(::AddServer(Engine, Address, Port));
    }

    void
    Start(uint16_t ListenPort = DEFAULT_QUICLAN_SERVER_PORT) {
        ASSERT_TRUE(::Start(Engine, ListenPort));
    }

    void
    SendPacket(const char* const DestAddr) {
        auto Packet = RequestPacket(Engine);

        // Populate packets with valid IPv4 header matching destination IP address
        PopulateHeader(
            (struct ip*) Packet->Buffer,
            v4Address.c_str(),
            DestAddr,
            Mtu);

        ASSERT_TRUE(Send(Engine, Packet));
    }

    void
    Stop() {
        ASSERT_TRUE(::Stop(Engine));
    }

    void
    WaitForIpAddress() {
        std::unique_lock lk(EngineMutex);
        EngineCv.wait(lk, [this]{return v4Address.length() > 0;});
        // printf("IP4 Address %s\n", 4Address.c_str());
        // printf("IP6 Address %s\n", v6Address.c_str());
    }

    void
    WaitForPacketReceived() {
        std::unique_lock lk(EngineMutex);
        EngineCv.wait(lk, [this]{return ReceivedData;});
    }

    void
    WaitForDisconnected() {
        std::unique_lock lk(EngineMutex);
        EngineCv.wait(lk, [this]{return Disconnected;});
    }
};

void
RunTest(
    TestEngine& ServerEngine,
    TestEngine& ClientEngine,
    bool ExpectConnectionFail)
{
    ServerEngine.Initialize();
    ClientEngine.Initialize();

    ClientEngine.AddServer("127.0.0.1");

    ServerEngine.Start();
    ClientEngine.Start(DEFAULT_QUICLAN_SERVER_PORT+1);

    if (ExpectConnectionFail) {
        ClientEngine.WaitForDisconnected();
        ServerEngine.Stop();
        ClientEngine.Stop();
        return;
    }

    ServerEngine.WaitForIpAddress();
    ClientEngine.WaitForIpAddress();

    ClientEngine.SendPacket(ServerEngine.v4Address.c_str());
    ServerEngine.SendPacket(ClientEngine.v4Address.c_str());

    ServerEngine.WaitForPacketReceived();
    ClientEngine.WaitForPacketReceived();

    ASSERT_TRUE(ServerEngine.ReceivedData);
    ASSERT_TRUE(ClientEngine.ReceivedData);

    ServerEngine.Stop();
    ClientEngine.Stop();
}

/*
    A basic test that just starts a client and server and connects and send a datagram packet through.
*/
TEST(E2E, TestBasicConnection)
{
    TestEngine Server;
    TestEngine Client;
    Server.Password = TestPassword;
    Client.Password = TestPassword;
    RunTest(Server, Client, false);
}

TEST(E2E, TestBasicConnectionEmptyPassword)
{
    TestEngine Server;
    TestEngine Client;
    RunTest(Server, Client, false);
}

TEST(E2E, TestBasicConnectionBadPassword)
{
    TestEngine Server;
    TestEngine Client;
    Server.Password = TestPassword;
    Client.Password = BadPassword;
    RunTest(Server, Client, true);
}
