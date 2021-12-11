/*
    Licensed under the MIT License.
*/
#pragma once

typedef struct QuicLanEngine QuicLanEngine;

typedef QUIC_BUFFER QuicLanPacket;

const uint16_t DEFAULT_QUICLAN_SERVER_PORT = 7490;

enum QuicLanTunnelEventType {
    InvalidTunnelEvent,
    TunnelIpAddressReady,   // Indicates the IP addresses to use in the tunnel.
    TunnelMtuChanged,       // Indicates the MTU of the tunnel.
    TunnelPacketReceived,   // Indicates a packet arrived destined for the tunnel.
    TunnelDisconnected      // Indicates the last connection has closed.
};

struct TunnelIpAddressReadyEvent {
    const char* IPv4Addr;
    const char* IPv6Addr;
};

struct TunnelMtuChangedEvent {
    uint16_t Mtu;
};

struct TunnelPacketReceivedEvent {
    const uint8_t * Packet;
    uint16_t PacketLength;
};

struct QuicLanTunnelEvent {
    QuicLanTunnelEventType Type;
    union {
        TunnelIpAddressReadyEvent   IpAddressReady;
        TunnelMtuChangedEvent       MtuChanged;
        TunnelPacketReceivedEvent   PacketReceived;
    };
};

typedef
void
(*FN_TUNNEL_EVENT_CALLBACK)(
    QuicLanTunnelEvent* Event,
    void* Context);

bool
InitializeQuicLanEngine(
    _In_z_ const char* Password,
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler,
    _In_ void* Context,
    _Out_ QuicLanEngine** Engine);

bool
AddServer(
    _In_ QuicLanEngine* Engine,
    _In_ const char* ServerAddress,
    _In_ uint16_t ServerPort);

bool
Start(
    _In_ QuicLanEngine* Engine,
    _In_ uint16_t ListenerPort);

QuicLanPacket*
RequestPacket(
    _In_ QuicLanEngine* Engine);

bool
Send(
    _In_ QuicLanEngine* Engine,
    _In_ QuicLanPacket* Packet);

bool
Stop(
    _In_ QuicLanEngine* Engine);

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine);
