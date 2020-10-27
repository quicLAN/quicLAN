/*
    Licensed under the MIT License.
*/

#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>
#undef min
#undef max

// These will have to be replaced to be platform indepdendent
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <mutex>
#include <condition_variable>
#include <stdio.h>

std::string Engine1v4Address;
std::string Engine1v6Address;
std::string Engine2v4Address;
std::string Engine2v6Address;
uint16_t Engine1Mtu = 0;
uint16_t Engine2Mtu = 0;
bool Engine1ReceivedData = false;
bool Engine2ReceivedData = false;

std::mutex Engine1Mutex;
std::mutex Engine2Mutex;

std::condition_variable Engine1Cv;
std::condition_variable Engine2Cv;

void
BasicConnectionListener1(QuicLanTunnelEvent* Event)
{
    switch (Event->Type) {
    case TunnelIpAddressReady: {
        std::unique_lock lk(Engine1Mutex);
        Engine1v4Address = Event->IpAddressReady.IPv4Addr;
        Engine1v6Address = Event->IpAddressReady.IPv6Addr;
        Engine1Mtu = Event->IpAddressReady.Mtu;
        lk.unlock();
        Engine1Cv.notify_all();
        break;
    }
    case TunnelPacketReceived: {
        std::unique_lock lk(Engine1Mutex);
        Engine1ReceivedData = true;
        lk.unlock();
        Engine1Cv.notify_all();
    }
        break;
    default:
        break;
    }
}

void
BasicConnectionListener2(QuicLanTunnelEvent* Event)
{
    switch (Event->Type) {
    case TunnelIpAddressReady: {
        std::unique_lock lk(Engine2Mutex);
        Engine2v4Address = Event->IpAddressReady.IPv4Addr;
        Engine2v6Address = Event->IpAddressReady.IPv6Addr;
        Engine2Mtu = Event->IpAddressReady.Mtu;
        lk.unlock();
        Engine2Cv.notify_all();
        break;
    }
    case TunnelPacketReceived: {
        std::unique_lock lk(Engine2Mutex);
        Engine2ReceivedData = true;
        lk.unlock();
        Engine2Cv.notify_all();
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
    QuicLanEngine* Engine1 = nullptr;
    QuicLanEngine* Engine2 = nullptr;
    QuicLanPacket* Engine1Packet = nullptr;
    QuicLanPacket* Engine2Packet = nullptr;

    if (!InitializeQuicLanEngine(BasicConnectionListener1, &Engine1)) {
        Result = false;
        printf("Failed initializing Engine1\n");
        goto Cleanup;
    }

    if (!InitializeQuicLanEngine(BasicConnectionListener2, &Engine2)) {
        Result = false;
        printf("Failed initializing Engine2\n");
        goto Cleanup;
    }

    if (!AddServer(Engine2, "127.0.0.1", DEFAULT_QUICLAN_SERVER_PORT)) {
        Result = false;
        printf("Failed adding server to Engine2\n");
        goto Cleanup;
    }

    if (!Start(Engine1, DEFAULT_QUICLAN_SERVER_PORT)) {
        Result = false;
        printf("Failed starting Engine1\n");
        goto Cleanup;
    }

    if (!Start(Engine2, DEFAULT_QUICLAN_SERVER_PORT+1)) {
        Result = false;
        printf("Failed starting Engine2\n");
        goto Cleanup;
    }

    Engine1Packet = RequestPacket(Engine1);
    Engine2Packet = RequestPacket(Engine2);

    {
        // Wait for Engine1 to get an IP address
        std::unique_lock lk(Engine1Mutex);
        Engine1Cv.wait(lk, []{return Engine1v4Address.length() > 0;});
    }
    {
        // Wait for Engine2 to get an IP address
        std::unique_lock lk(Engine2Mutex);
        Engine2Cv.wait(lk, []{return Engine2v4Address.length() > 0;});
    }

    // Populate packets with valid IPv4 header matching destination IP address
    PopulateHeader(
        (struct ip*) Engine1Packet->Buffer,
        Engine1v4Address.c_str(),
        Engine2v4Address.c_str(),
        Engine1Mtu);

    PopulateHeader(
        (struct ip*) Engine2Packet->Buffer,
        Engine2v4Address.c_str(),
        Engine1v4Address.c_str(),
        Engine2Mtu);

    if (!Send(Engine1, Engine1Packet)) {
        Result = false;
        printf("Failed sending Engine1\n");
        goto Cleanup;
    }
    if (!Send(Engine2, Engine2Packet)) {
        Result = false;
        printf("Failed sending Engine2\n");
        goto Cleanup;
    }

    {
        // Wait for Engine1 to get a packet
        std::unique_lock lk(Engine1Mutex);
        Engine1Cv.wait(lk, []{return Engine1ReceivedData;});
    }
    {
        // Wait for Engine2 to get a packet
        std::unique_lock lk(Engine2Mutex);
        Engine2Cv.wait(lk, []{return Engine2ReceivedData;});
    }

    assert(Engine1ReceivedData);
    assert(Engine2ReceivedData);

    printf("Packets received and test passed!\n");

    if (!Stop(Engine1)) {
        Result = false;
        printf("Failed stopping Engine1\n");
    }
    if (!Stop(Engine2)) {
        Result = false;
        printf("Failed stopping Engine2\n");
    }

Cleanup:
    UninitializeQuicLanEngine(Engine1);
    UninitializeQuicLanEngine(Engine2);

    return Result;
}


int main(int argc, char** argv)
{
    return TestBasicConnection();
}