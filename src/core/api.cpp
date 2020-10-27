/*
    Licensed under the MIT License.
*/
#include "precomp.h"

bool
InitializeQuicLanEngine(
    _In_ FN_TUNNEL_EVENT_CALLBACK EventHandler,
    _Out_ QuicLanEngine** Engine)
{
    if (Engine == nullptr) {
        return false;
    }
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
Start(
    _In_ QuicLanEngine* Engine,
    _In_ uint16_t ListenerPort)
{
    if (Engine == nullptr) {
        return false;
    }
    if (strnlen(Engine->ServerAddress, sizeof(Engine->ServerAddress)) != 0) {
        //
        // Start a connection to an existing VPN, and wait for the connection
        // to complete before returning from this call.
        //
        if (!Engine->StartClient()) {
            return false;
        }
    }

    return Engine->StartServer(ListenerPort);
}

bool
AddServer(
    _In_ QuicLanEngine* Engine,
    _In_ const char* ServerAddress,
    _In_ uint16_t ServerPort)
{
    if (Engine == nullptr) {
        return false;
    }
    strncpy(Engine->ServerAddress, ServerAddress, sizeof(Engine->ServerAddress));
    Engine->ServerPort = ServerPort;
    return true;
}

QuicLanPacket*
RequestPacket(
    _In_ QuicLanEngine* Engine)
{
    if (Engine == nullptr) {
        return nullptr;
    }
    return Engine->GetPacket();
}

bool
Send(
    _In_ QuicLanEngine* Engine,
    _In_ QuicLanPacket* Packet)
{
    if (Engine == nullptr) {
        return false;
    }
    return Engine->Send(Packet);
}

bool
Stop(
    _In_ QuicLanEngine* Engine)
{
    if (Engine == nullptr) {
        return false;
    }
    return Engine->Stop();
}

void
UninitializeQuicLanEngine(
    _In_ QuicLanEngine* Engine)
{
    if (Engine != nullptr) {
        delete Engine;
    }
}