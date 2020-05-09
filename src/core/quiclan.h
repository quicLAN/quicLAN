/*
    Licensed under the MIT License.
*/
#pragma once

typedef struct QuicLanEngine QuicLanEngine;

enum QuicLanTunnelEventType {
    InvalidTunnelEvent,
    TunnelIpAddressReady,
    TunnelPacketReceived,
    TunnelSendComplete,
    TunnelDisconnected
};

struct TunnelIpAddressReadyEvent {
    const char* IPv4Addr;
    const char* IPv6Addr;
    uint16_t Mtu;
};

struct TunnelPacketReceivedEvent {
    const uint8_t * const Packet;
    uint16_t PacketLength;
};

struct TunnelSendCompleteEvent {
    uint8_t * Packet;
};

struct QuicLanTunnelEvent {
    QuicLanTunnelEventType Type;
    union {
        TunnelIpAddressReadyEvent   IpAddressReady;
        TunnelPacketReceivedEvent   PacketReceived;
        TunnelSendCompleteEvent     SendComplete;
    };
};

typedef
void
(*FN_TUNNEL_EVENT_CALLBACK)(
    QuicLanTunnelEvent* Event);

bool
InitializeQuicLanEngine(
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler,
    _Out_ QuicLanEngine** Engine);

bool
AddServer(
    _In_ QuicLanEngine* Engine,
    _In_ const char* ServerAddress,
    _In_ uint16_t ServerPort);

bool
Start(
    _In_ QuicLanEngine* Engine);

bool
Send(
    _In_ QuicLanEngine* Engine,
    _In_ const uint8_t* Packet,
    _In_ uint16_t PacketLength);

bool
Stop(
    _In_ QuicLanEngine* Engine);

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine);
