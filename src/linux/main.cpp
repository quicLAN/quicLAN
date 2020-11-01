
/*
    Licensed under the MIT License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <thread>


#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>

QuicLanEngine *Engine;
int TunnelFile;
char TunnelName[IFNAMSIZ];
uint16_t TunnelMtu = 0;

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, ret;
    /* open file to tunnel device */
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        err(errno, "Failed to open /dev/net/tun: %d\n", errno);
        return errno;
    }
    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if( *dev )
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
       err(errno, "ioctl failed: %s\n", dev);
       close(fd);
       return errno;
    }
    strcpy(dev, ifr.ifr_name);

    return fd;
}
void
TunnelReadThread() {
    while (true) {
        QuicLanPacket* Packet = RequestPacket(Engine);
        int bytes = read(TunnelFile, Packet->Buffer, Packet->Length);
        if (bytes == -1) {
            printf("Error reading from tunnel: %d!\n", errno);
            continue;
        } else if (bytes == 0) {
            printf("Tunnel closed!\n");
            break;
        } else {
            Packet->Length = (uint32_t)bytes;
        }
        if (!Send(Engine, Packet)) {
            printf("Failed to send data!\n");
        }
    }
}

void TunnelEventCallback(QuicLanTunnelEvent* Event) {
    switch (Event->Type) {
        case TunnelIpAddressReady: {
            struct ifreq ifr;
            strncpy(ifr.ifr_name, TunnelName, IFNAMSIZ); // TODO: use the actually allocated name
            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if(sock == -1){
                err(errno, "Could not get socket.\n");
                return;
            }

            // Start tunnel read thread
            std::thread(TunnelReadThread).detach();

            /* Set IP address */
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            /* Convert IP from string to network format */
            inet_aton(Event->IpAddressReady.IPv4Addr, &sin.sin_addr);
            memcpy(&ifr.ifr_addr, &sin, sizeof(ifr.ifr_addr));
            if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
                err(errno, "ioctl to set ip address failed\n");
                close(sock);
                return;
            }

            /* Bring interface up */
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
                err(errno, "ioctl to get flags failed\n");
                close(sock);
                return;
            }
            ifr.ifr_flags |= IFF_UP;
            if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
                err(errno, "ioctl to set flags failed\n");
                close(sock);
                return;
            }

            close(sock);
            break;
            }
        case TunnelMtuChanged: {
            struct ifreq ifr;
            strncpy(ifr.ifr_name, TunnelName, IFNAMSIZ); // TODO: use the actually allocated name
            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if(sock == -1){
                err(errno, "Could not get socket.\n");
                return;
            }

            /* Set MTU */
            if(ioctl(sock, SIOCGIFMTU, &ifr)) {
                err(errno, "ioctl to get MTU failed\n");
                close(sock);
                return;
            }
            printf("Setting MTU to %u\n", Event->MtuChanged.Mtu);
            ifr.ifr_mtu = TunnelMtu = Event->MtuChanged.Mtu;
            if(ioctl(sock, SIOCSIFMTU, &ifr)) {
                err(errno, "ioctl to change MTU failed\n");
                close(sock);
                return;
            }

            close(sock);
            break;
            }
        case TunnelPacketReceived:
            printf("Packet received\n");
            write(TunnelFile, Event->PacketReceived.Packet, Event->PacketReceived.PacketLength);
            break;
        case TunnelDisconnected:
            printf("Tunnel Disconnected!\n");
            break;
        default:
            break;
    }
}


int main(int argc, char** argv)
{
    int junk;
    if (!InitializeQuicLanEngine("ToDo:GetFromCommandline", TunnelEventCallback, &Engine)) {
        printf("Failed to initialize QuicLanEngine!\n");
        return -1;
    }

    if (strcmp(argv[1], "-c") == 0 && argc >= 3) {
        const char* ServerAddress = argv[2];
        printf("Server address: %s\n", ServerAddress);
        if (!AddServer(Engine, ServerAddress, DEFAULT_QUICLAN_SERVER_PORT)) {
            printf("Failed to add server\n");
            return -1;
        }

    } else if (strcmp(argv[1], "-s") == 0) {
        // TODO: Set server address/port
    } else {
        printf("Invalid parameters!\n");
    }

    strncpy(TunnelName, "quiclan0", sizeof(TunnelName));
    TunnelFile = tun_alloc(TunnelName);
    if (TunnelFile <= 0) {
        printf("Failed to create tunnel!\n");
        return -1;
    }
    // TODO: drop root privileges and use the tunnel.
    if(!Start(Engine, DEFAULT_QUICLAN_SERVER_PORT)) {
        printf("Failed to start quiclan!\n");
        return -1;
    }

    scanf("Press any key to exit");

    return 0;
}
