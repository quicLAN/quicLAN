#pragma once

struct QuicLanServer {

    bool Initialize();

    bool
    Connect(
        _In_opt_ const char* ServerAddress,
        _In_opt_ uint16_t ServerPort,
        _Out_ char* ClientIpv4Addr,
        _Out_ char* ClientIpv6Addr);

    void
    SetVpnClientPort(
        _In_ uint16_t ClientPort);

    ~QuicLanServer();

    static
    _Function_class_(QUIC_LISTENER_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerListenerCallback(
        _In_ HQUIC Listener,
        _In_opt_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event);

    static
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientConnectionCallback(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event);

    static
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ControlStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event);

    const QUIC_API_TABLE* MsQuic;
    HQUIC Registration;
    HQUIC Session;
    QUIC_SEC_CONFIG* SecurityConfig;

    QUIC_EVENT ConnectedEvent;

    HQUIC PrimaryConnection;
    std::vector<HQUIC> Peers;

    uint16_t MaxDatagramLength = 1000;
};
