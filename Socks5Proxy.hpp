#ifndef HGUARD_SOCKS5_PROXY
#define HGUARD_SOCKS5_PROXY

#include "Proxy.hpp"

class Socks5Proxy : public virtual Proxy {
protected:
    Socks5Proxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress):
        Proxy(settings, clientAddress, targetAddress)
    {
    }

    void socks5_greet_and_authenticate(int proxySocketFd) {
        char packet[65536] = {};
        size_t packetLen = 0;

#pragma pack(push, 1)
        struct Socks5AvailableMethodsPacket {
            uint8_t version;
            uint8_t method_count;
        };
        struct Socks5ChosenMethodPacket {
            uint8_t version;
            uint8_t method;
        };
#pragma pack(pop)

        std::vector<uint8_t> methods;
        methods.emplace_back(0x00);
        if (!settings.username.empty()) {
            methods.emplace_back(0x02);
        }

        Socks5AvailableMethodsPacket request = {5, uint8_t(methods.size())};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request, sizeof(request)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, methods.data(), sizeof(uint8_t) * methods.size()) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during auth negotiation");
        }

        Socks5ChosenMethodPacket response = {};

        if (read_exactly(proxySocketFd, &response, sizeof(response)) != sizeof(response)) {
            throw std::runtime_error("read from upstream proxy failed during auth negotiation");
        }

        if (response.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
        switch (response.method) {
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
    }

    /// Perform the main request, asking to put us through to the target machine.
    ///
    /// SOCKS5 cmd values:
    ///   1: CONNECT
    ///   2: BIND (not really useful for us)
    ///   3: UDP ASSOCIATE
    ///
    /// returns the BND.ADDR and BND.PORT as a struct sockaddr_in.
    struct sockaddr_in socks5_request_tunnel(int proxySocketFd, uint8_t cmd) {
        char packet[65536] = {};
        size_t packetLen = 0;

#pragma pack(push, 1)
        struct Socks5RequestResponsePacket {
            uint8_t version;
            uint8_t command;
            uint8_t reserved;
            uint8_t address_type; // Must be 1 for our purposes.
        };
#pragma pack(pop)
        Socks5RequestResponsePacket request = {5, cmd, 0, 1};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request, sizeof(request)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_addr.s_addr, sizeof(targetAddress.sin_addr.s_addr)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_port, sizeof(targetAddress.sin_port)) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during main request");
        }

        Socks5RequestResponsePacket response = {};

        if (read_exactly(proxySocketFd, &response, sizeof(response)) != sizeof(response)) {
            throw std::runtime_error("read from upstream proxy failed during main request");
        }

        if (response.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        switch (response.command) {
        case 0:
            // Success!
            break;
        case 1:
            throw std::runtime_error("upstream proxy experienced a general SOCKS server failure");
        case 2:
            throw std::runtime_error("upstream proxy rejected connection not allowed by ruleset");
        default:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        }

        struct sockaddr_in bndAddress = {};
        bndAddress.sin_family = AF_INET;
        char addressData[256] = {};
        switch (response.address_type) {
        case 1:
            if (read_exactly(proxySocketFd, &addressData, 4) != sizeof(response)) {
                throw std::runtime_error("read from upstream proxy failed during CONNECT");
            }
            bndAddress.sin_addr.s_addr = *((uint32_t*)addressData); // Preserve network byte order.
            break;
        case 3:
            {
                uint8_t len;
                if (read_exactly(proxySocketFd, &len, sizeof(len)) != sizeof(len)) {
                    throw std::runtime_error("read from upstream proxy failed during main request");
                }
                if (len == 0) {
                    throw std::runtime_error("upstream proxy sent zero-length domain");
                }
                if (read_exactly(proxySocketFd, &addressData, len) != len) {
                    throw std::runtime_error("read from upstream proxy failed during request");
                }
                addressData[len] = 0; // null terminate
                struct hostent *server = gethostbyname(addressData); // replace with getaddrinfo() later
                if (server == nullptr) {
                    throw std::runtime_error("cannot resolve address returned by upstream proxy");
                }
                if (server->h_addrtype != AF_INET) {
                    throw std::runtime_error("FIXME: Resolved to IPv6 address. Use getaddrinfo() instead.");
                }
                bcopy((char*)server->h_addr, &bndAddress.sin_addr.s_addr, server->h_length);
            }
            break;
        case 4:
            if (read_exactly(proxySocketFd, &addressData, 16) != 16) {
                throw std::runtime_error("read from upstream proxy failed during main request");
            }
            throw std::runtime_error("upstream proxy returned IPv6 address (unsupported)");
            // break;
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        if (read_exactly(proxySocketFd, &bndAddress.sin_port, 2) != 2) {
            throw std::runtime_error("read from upstream proxy failed during main request");
        }
        return bndAddress;
    }
};

#endif
