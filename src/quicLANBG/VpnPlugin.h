#pragma once


namespace winrt::quicLANBG::implementation
{
    enum HandshakeState
    {
        Waiting,
        Received,
        Canceled
    };

    struct VpnPlugin : implements<VpnPlugin, winrt::Windows::Networking::Vpn::IVpnPlugIn>
    {
        VpnPlugin() = default;

        void Connect(Windows::Networking::Vpn::VpnChannel const& channel);
        void Disconnect(Windows::Networking::Vpn::VpnChannel const& channel);
        void GetKeepAlivePayload(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer& keepAlivePacket);
        void Encapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBufferList const& packets, Windows::Networking::Vpn::VpnPacketBufferList const& encapulatedPackets);
        void Decapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer const& encapBuffer, Windows::Networking::Vpn::VpnPacketBufferList const& decapsulatedPackets, Windows::Networking::Vpn::VpnPacketBufferList const& controlPacketsToSend);

        void ConnectionReceived(Windows::Networking::Sockets::StreamSocketListener  sender, Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs args);
        void MessageReceived(Windows::Networking::Sockets::DatagramSocket sender, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs args);

    private:
        void Handshake(Windows::Networking::Sockets::DatagramSocket const& tunnel, std::atomic<HandshakeState> const& handshakeState, std::wstring const& secret);
        void Configure(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Sockets::StreamSocket& socket);
        Windows::Networking::Sockets::DatagramSocket m_serverDatagramSocket;
        Windows::Networking::Sockets::StreamSocketListener m_streamSocketListener;
        std::vector<Windows::Networking::Sockets::StreamSocket> m_clientSockets;
    };

    struct VpnPluginContext : implements<VpnPluginContext, winrt::Windows::Foundation::IInspectable>
    {
        friend struct VpnPlugin;

        VpnPluginContext() = default;

    private:
        std::atomic<HandshakeState> handshakeState{ Waiting };
    };
}
