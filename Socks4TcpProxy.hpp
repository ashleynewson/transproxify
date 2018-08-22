#ifndef HGUARD_SOCKS4_TCP_PROXY
#define HGUARD_SOCKS4_TCP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "TcpProxy.hpp"

class Socks4TcpProxy : public TcpProxy {
public:
    Socks4TcpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress, int clientSocketFd):
        Proxy(settings, clientAddress, targetAddress),
        TcpProxy(settings, clientAddress, targetAddress, clientSocketFd)
    {
    }

private:
    void proxy_negotiate(int proxySocketFd) override {
#pragma pack(push, 1)
        struct Socks4Packet {
            uint8_t version;
            uint8_t command; // or response
            uint16_t dest_port;
            uint32_t dest_address;
        };
#pragma pack(pop)

        char packet[65536] = {};
        size_t packetLen = 0;

        Socks4Packet request = {4, 1, targetAddress.sin_port, targetAddress.sin_addr.s_addr};

        const char* userId;
        size_t userIdLen;
        if (!settings.username.empty()) {
            userId = settings.username.c_str();
        } else if (!settings.password.empty()) {
            userId = settings.password.c_str();
        } else {
            userId = "";
        }
        userIdLen = strlen(userId)+1;

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request, sizeof(request)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, userId, userIdLen) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        Socks4Packet response = {};

        if (read_exactly(proxySocketFd, &response, sizeof(response)) != sizeof(response)) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }

        if (response.version != 0) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        switch (response.command) {
        case 90:
            // Success!
            break;
        case 91:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        case 92:
        case 93:
            throw std::runtime_error("upstream proxy identd authentication failure");
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
    }
};

#endif
