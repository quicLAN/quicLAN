#include "pch.h"
#include "VpnPlugin.h"
//#include "../strutil.h"

using namespace winrt;
using namespace Windows::Networking;
using namespace Windows::Networking::Vpn;
using namespace Windows::Networking::Sockets;
using namespace Windows::Storage::Streams;

using namespace std::chrono_literals;

namespace winrt::quicLANBG::implementation
{
    constexpr int MAX_HANDSHAKE_ATTEMPTS = 50;
    constexpr auto IDLE_INTERVAL = 100ms;
    constexpr auto SERVER_ADDRESS = L"127.0.0.1";
    constexpr auto CLIENT_PORT = L"4441";
    constexpr auto SERVER_PORT = L"4444";

    constexpr int MAX_PACKET_SIZE = 1000;

    void VpnPlugin::Connect(VpnChannel const& channel)
    {
        auto token = m_serverDatagramSocket.MessageReceived({ this, &VpnPlugin::MessageReceived });

        try {
            m_serverDatagramSocket.BindEndpointAsync({ SERVER_ADDRESS }, SERVER_PORT).get();
            //m_serverDatagramSocket.BindServiceNameAsync(SERVER_PORT).get();
            //m_streamSocketListener.BindEndpointAsync({ SERVER_ADDRESS }, SERVER_PORT).get();
            //m_streamSocketListener.BindServiceNameAsync(SERVER_PORT).get();
        } catch (winrt::hresult_error const& ex) {
            std::cout << "ERROR!" << ex.code() << ": " << ex.message().data() << std::endl;
        }

        try
        {
            HostName serverHostname{ SERVER_ADDRESS };
            auto context = channel.PlugInContext().as<VpnPluginContext>();
            if (!context)
            {
                context = make<VpnPluginContext>().as<VpnPluginContext>();
                channel.PlugInContext(context.as<IInspectable>());
            }

            DatagramSocket tunnel;
            // Without these, nullptr crash at start()
            // Can't start tunnel before this call either
            //channel.AddAndAssociateTransport(tunnel, serverHostname);
            channel.AssociateTransport(tunnel, nullptr);

            hstring parametershs;


            std::wstring port, secret;

            //Windows::Data::Xml::Dom::XmlDocument doc;
            //doc.LoadXml(channel.Configuration().CustomField());
            //auto root = doc.FirstChild();
            //if (root.NodeName() == L"quiclan-config")
            //{
            //    for (auto node : root.ChildNodes())
            //    {
            //        if (node.NodeName() == L"port")
            //            port = node.InnerText();
            //        else if (node.NodeName() == L"secret")
            //            secret = node.InnerText();
            //    }
            //}

            tunnel.ConnectAsync(serverHostname, SERVER_PORT).get(); // without this, no crash at start(), but no connection either. doing it async doesn't help either.

            uint32_t mtuSize = 1200;
            std::vector<HostName> IPv4AddrList;
            std::vector<HostName> IPv6AddrList;
            VpnRouteAssignment route;
            //route.ExcludeLocalSubnets(true);
            auto IPv4Routes = route.Ipv4InclusionRoutes();
            auto IPv6Routes = route.Ipv6InclusionRoutes();
            std::vector<HostName> dnsServerList;

            //IPv4AddrList.push_back({ L"10.137.137.37" });
            IPv4AddrList.push_back({ L"169.254.1.40" });
            IPv6AddrList.push_back({ L"[fd71:7569:636c:616e::1]" });
            //dnsServerList.push_back({ L"10.137.137.1" });
            //IPv4Routes.Append({ {L"10.137.137.0"}, 24 });
            IPv4Routes.Append({ {L"169.254.0.0"}, 16 });
            IPv6Routes.Append({ {L"[fd71:7569:636c:616e::]"}, 64 });

            VpnDomainNameAssignment assignment{};
            assignment.DomainNameList().Append({ L"foobar", VpnDomainNameType::Suffix, dnsServerList, nullptr });
            //auto ifIdFactory = IVpnInterfaceIdFactory();
            auto ifId = VpnInterfaceId(
                { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }
                //{ 0xfd, 0x71,0x75,0x69,0x63,0x6c,0x61,0x6e,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }
                //{ 0xfd,0x71,} 0x75,0x69, 0x63,0x6c,0x61,0x6e, }
                //0xfe,0x80, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0xad, 0xec,0x74,0x1c,0x71,0x17,0x7e,0xf7 }
            );

            //channel.StartExistingTransports(
            channel.StartWithMainTransport(
                IPv4AddrList,
                IPv6AddrList,
                nullptr,
                route,
                assignment,
                MAX_PACKET_SIZE,
                MAX_PACKET_SIZE + 1,
                false,
                tunnel
            );
            //Configure(channel, tunnel);

            // This is apparently unreachable.
            //tunnel.ConnectAsync(serverHostname, SERVER_PORT).get(); // without this, no crash at start(), but no connection either...
        }
        catch (hresult_error const& ex)
        {
            channel.TerminateConnection(ex.message());
        }
    }

    void VpnPlugin::Disconnect(VpnChannel const& channel)
    {
        try
        {
            auto context = channel.PlugInContext().as<VpnPluginContext>();
            if (!context)
            {
            }
            else
            {
                context->handshakeState.store(HandshakeState::Canceled);
                channel.Stop();
            }
            //m_streamSocketListener.Close();
        }
        catch (winrt::hresult_error const&)
        {
        }
        channel.PlugInContext(nullptr);
    }

    void VpnPlugin::GetKeepAlivePayload(VpnChannel const& /*channel*/, VpnPacketBuffer& /*keepAlivePacket*/)
    {
    }

    void VpnPlugin::Encapsulate(VpnChannel const& channel, VpnPacketBufferList const& packets, VpnPacketBufferList const& encapulatedPackets)
    {
        //auto lengthPacket = channel.GetVpnSendPacketBuffer();
        uint32_t length = 0;
        while (packets.Size() > 0)
        {
            VpnPacketBuffer pkt = packets.RemoveAtBegin();
            length += pkt.Buffer().Length();
            encapulatedPackets.Append(pkt);
        }
        //auto buf = lengthPacket.Buffer();
        //*((uint32_t*)buf.data()) = length;
        //buf.Length(sizeof(uint32_t));
        //encapulatedPackets.AddAtBegin(lengthPacket);
    }

    void VpnPlugin::Decapsulate(VpnChannel const& channel, VpnPacketBuffer const& encapBuffer, VpnPacketBufferList const& decapsulatedPackets, VpnPacketBufferList const& /*controlPacketsToSend*/)
    {
        auto vpnbuf = channel.GetVpnReceivePacketBuffer();
        auto buf = vpnbuf.Buffer();
        auto encapbuf = encapBuffer.Buffer();
        auto len = encapbuf.Length();
        if (len > buf.Capacity())
        {
            return;
        }

        memcpy(buf.data(), encapbuf.data(), len);
        buf.Length(len);
        decapsulatedPackets.Append(vpnbuf);
    }

    void VpnPlugin::Handshake(DatagramSocket const& tunnel, std::atomic<HandshakeState> const& handshakeState, std::wstring const& secret)
    {
        for (int i = 0; i < 3; ++i)
        {
            DataWriter writer{ tunnel.OutputStream() };
            writer.UnicodeEncoding(UnicodeEncoding::Utf8);
            writer.WriteByte(0);
            writer.WriteString(secret);
            writer.StoreAsync().get();
            writer.DetachStream();
        }

        for (int i = 0; i < MAX_HANDSHAKE_ATTEMPTS; ++i)
        {
            std::this_thread::sleep_for(IDLE_INTERVAL);

            switch (handshakeState.load())
            {
            case HandshakeState::Received:
                return;
            case HandshakeState::Canceled:
                throw hresult_canceled{};
            }
        }

        throw hresult_error{ E_FAIL, L"Operation timed out" };
    }

    void VpnPlugin::Configure(Windows::Networking::Vpn::VpnChannel const & channel, Windows::Networking::Sockets::StreamSocket& socket)
    {
        //std::wstring_view parameters{ parametershs };
        //rtrimwsv(parameters);

        uint32_t mtuSize = MAX_PACKET_SIZE;
        std::vector<HostName> IPv4AddrList;
        VpnRouteAssignment route;
        route.ExcludeLocalSubnets(true);
        auto IPv4Routes = route.Ipv4InclusionRoutes();
        std::vector<HostName> dnsServerList;

        //for (auto const& parameter : splitwsv(parameters))
        //{
        //    auto fields = splitws(parameter, L',');
        //    try
        //    {
        //        switch (fields[0].at(0))
        //        {
        //        case 'm':
        //            mtuSize = stoul(fields.at(1));
        //            break;
        //        case 'a':
        //            IPv4AddrList.emplace_back(fields.at(1));
        //            break;
        //        case 'r':
        //            IPv4Routes.Append({ {fields.at(1)}, static_cast<uint8_t>(stoul(fields.at(2))) });
        //            break;
        //        case 'd':
        //            dnsServerList.emplace_back(fields.at(1));
        //            break;
        //        }
        //    }
        //    catch (std::out_of_range const&)
        //    {
        //        throw hresult_invalid_argument{ L"Bad parameter: " + parameter };
        //    }
        //}

        IPv4AddrList.push_back({ L"10.137.137.37" });
        dnsServerList.push_back({ L"10.137.137.1" });
        IPv4Routes.Append({ {L"10.137.137.0"}, 24 });

        VpnDomainNameAssignment assignment;
        assignment.DomainNameList().Append({ L".", VpnDomainNameType::Suffix, dnsServerList, nullptr });

        //channel.StartExistingTransports(
        channel.StartWithMainTransport(
            IPv4AddrList,
            nullptr,
            nullptr,
            route,
            assignment,
            mtuSize,
            MAX_PACKET_SIZE,
            false,
            socket
        );
    }

    void VpnPlugin::ConnectionReceived(StreamSocketListener /* sender */, StreamSocketListenerConnectionReceivedEventArgs args)
    {
        //StreamSocket socket{ args.Socket() }; // Keep the socket referenced, and alive.

                //m_clientSockets.emplace_back( args.Socket() );

                //std::thread([](StreamSocket& socket){
        //StreamSocket localSocket{ args.Socket() };
        try
        {
            auto socket{ args.Socket() };
            DataReader dataReader{ args.Socket().InputStream() };
            DataWriter dataWriter{ args.Socket().OutputStream() };
            m_streamSocketListener.Close();

            while (true) {
                unsigned int bytesLoaded = dataReader.LoadAsync(sizeof(unsigned int)).get();

                unsigned int stringLength = dataReader.ReadUInt32();
                bytesLoaded = dataReader.LoadAsync(stringLength).get();
                auto request = dataReader.ReadBuffer(bytesLoaded);

                // Echo the request back as the response.
                //dataWriter.WriteUInt32(request.Length());
                dataWriter.WriteBuffer(request);
                dataWriter.StoreAsync().get();
            }
        }
        catch (winrt::hresult_error const& ex)
        {
            std::cout << "ERROR!" << ex.code() << ": " << ex.message().data() << std::endl;
        }
        //},
        //m_clientSockets.back()
        //).detach();
    }

    void VpnPlugin::MessageReceived(Windows::Networking::Sockets::DatagramSocket sender, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs args)
    {
        DataReader dataReader{ args.GetDataReader() };
        auto request{ dataReader.ReadBuffer(dataReader.UnconsumedBufferLength()) };

        // Echo the request back as the response.
        IOutputStream outputStream = sender.GetOutputStreamAsync(args.RemoteAddress(), args.RemotePort()).get();
        DataWriter dataWriter{ outputStream };
        dataWriter.WriteBuffer(request);

        std::cout << "Echoing packet back of size: " << request.Length() << std::endl;

        dataWriter.StoreAsync().get();
    }
}
