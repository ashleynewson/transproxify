#ifndef HGUARD_SOCKS5_TCP_PROXY
#define HGUARD_SOCKS5_TCP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "TcpProxy.hpp"

class Socks5TcpProxy : public TcpProxy {
public:
    Socks5TcpProxy(ProxySettings settings, int clientSocketFd):
        TcpProxy(settings, clientSocketFd)
    {
    }

private:
    void proxy_negotiate(int proxySocketFd) {
#pragma pack(push, 1)
        struct Socks5Packet1 {
            uint8_t version;
            uint8_t method_count;
        };
        struct Socks5Packet2 {
            uint8_t version;
            uint8_t method;
        };
        struct Socks5Packet3 {
            uint8_t version;
            uint8_t command;
            uint8_t reserved;
            uint8_t address_type; // Must be 1 for our purposes.
        };
#pragma pack(pop)

        char packet[65536] = {};
        size_t packetLen = 0;

        std::vector<uint8_t> methods;
        methods.emplace_back(0x00);
        if (!settings.username.empty()) {
            methods.emplace_back(0x02);
        }

        Socks5Packet1 request1 = {5, uint8_t(methods.size())};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request1, sizeof(request1)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, methods.data(), sizeof(uint8_t) * methods.size()) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during auth negotiation");
        }

        Socks5Packet2 response1 = {};

        if (read_exactly(proxySocketFd, &response1, sizeof(response1)) != sizeof(response1)) {
            throw std::runtime_error("read from upstream proxy failed during auth negotiation");
        }

        if (response1.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
        switch (response1.method) {
        case 0x00:
            break;
        case 0x02:
            if (settings.username.empty()) {
                // Protocol mismatch?
                throw std::runtime_error("upstream proxy selected username and password authentication where no authentication was expected");
            }
            {
                uint8_t version = 1;
                // Lengths already checked in ProxySettings
                uint8_t usernameLen = settings.username.length();
                const char* username = settings.username.c_str();
                uint8_t passwordLen = settings.password.length();
                const char* password = settings.password.c_str();

                packetLen = 0;
                if (build_packet(packet, sizeof(packet), &packetLen, &version, sizeof(version)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, &usernameLen, sizeof(usernameLen)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, username, usernameLen) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, &passwordLen, sizeof(passwordLen)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, password, passwordLen) < 0
                    || write_exactly(proxySocketFd, packet, packetLen) < 0
                    )
                {
                    throw std::runtime_error("write to upstream proxy failed during authentication");
                }
                if (read_exactly(proxySocketFd, &version, sizeof(version)) != sizeof(version)) {
                    throw std::runtime_error("read from upstream proxy failed during authentication");
                }
                if (version != 1) {
                    throw std::runtime_error("upstream proxy protocol mismatch");
                }
                uint8_t status = 0;
                if (read_exactly(proxySocketFd, &status, sizeof(status)) != sizeof(status)) {
                    throw std::runtime_error("read from upstream proxy failed during authentication");
                }
                if (status != 0) {
                    throw std::runtime_error("upstream proxy authentication failure");
                }
            }
            break;
        case 0xff:
            throw std::runtime_error("upstream proxy no authentication method");
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        Socks5Packet3 request2 = {5, 1, 0, 1};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request2, sizeof(request2)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_addr.s_addr, sizeof(targetAddress.sin_addr.s_addr)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_port, sizeof(targetAddress.sin_port)) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        Socks5Packet3 response2 = {};

        if (read_exactly(proxySocketFd, &response2, sizeof(response2)) != sizeof(response2)) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }

        if (response2.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        switch (response2.command) {
        case 0:
            // Success!
            break;
        case 2:
            throw std::runtime_error("upstream proxy rejected connection not allowed by ruleset");
        default:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        }

        char discard[256] = {};
        switch (response2.address_type) {
        case 1:
            if (read_exactly(proxySocketFd, &discard, 4) != sizeof(response2)) {
                throw std::runtime_error("read from upstream proxy failed during CONNECT");
            }
            break;
        case 3:
            {
                uint8_t len;
                if (read_exactly(proxySocketFd, &len, sizeof(len)) != sizeof(len)) {
                    throw std::runtime_error("read from upstream proxy failed during CONNECT");
                }
                if (len == 0) {
                    throw std::runtime_error("upstream proxy sent zero-length domain");
                }
                if (read_exactly(proxySocketFd, &discard, len) != len) {
                    throw std::runtime_error("read from upstream proxy failed during CONNECT");
                }
            }
            break;
        case 4:
            if (read_exactly(proxySocketFd, &discard, 16) != 16) {
                throw std::runtime_error("read from upstream proxy failed during CONNECT");
            }
            break;
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        if (read_exactly(proxySocketFd, &discard, 2) != 2) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }
    }
};

#endif
