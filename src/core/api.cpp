/*
    Licensed under the MIT License.
*/
#include "precomp.h"

bool
Start(
    _In_ QuicLanEngine* Engine)
{
    if (strnlen(Engine->ServerAddress, sizeof(Engine->ServerAddress)) != 0) {
        //
        // Start a connection to an existing VPN, and wait for the connection
        // to complete before returning from this call.
        //
        if (!Engine->StartClient()) {
            return false;
        }
    }

    return Engine->StartServer();
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
    // TODO: Don't allow the app to send unrestricted, apply back pressure from QUIC.
    // Consider forcing the app to request a buffer from us in a lookaside list
    // which allows us to apply back pressure.
    QUIC_BUFFER* Buffer = new QUIC_BUFFER;
    Buffer->Buffer = (uint8_t*) Packet;
    Buffer->Length = PacketLength;

    return Engine->Send(Buffer);
}

bool
Stop(
    _In_ QuicLanEngine* Engine)
{
    return Engine->Stop();
}

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine)
{
    delete Engine;
}