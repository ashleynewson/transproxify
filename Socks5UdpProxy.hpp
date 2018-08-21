#ifndef HGUARD_SOCKS5_UDP_PROXY
#define HGUARD_SOCKS5_UDP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "UdpProxy.hpp"
#include "Socks5Proxy.hpp"

#define MAXIMUM_IPV4_UDP_PAYLOAD 65507

class Socks5UdpProxy : public UdpProxy, public Socks5Proxy {
private:
    int proxySocketFd;
    Cleaner proxySocketFdCleaner;
    struct sockaddr_in relayAddress;
    int relaySocketFd;
    Cleaner relaySocketFdCleaner;

public:
    Socks5UdpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress):
        Proxy(settings, clientAddress, targetAddress),
        UdpProxy(settings, clientAddress, targetAddress),
        Socks5Proxy(settings, clientAddress, targetAddress)
    {
        // Establish connection to proxy. This is just left alone
        // after negotiation, which may be a bad way to do things. We
        // don't bother with TCP keepalives.
        proxySocketFd = socket(AF_INET, SOCK_STREAM, 0);
        proxySocketFdCleaner = Cleaner([this] {
                close(this->proxySocketFd);
            });

        if (connect(proxySocketFd, (struct sockaddr*)&settings.proxyAddress, sizeof(settings.proxyAddress)) < 0) {
            throw std::runtime_error("could not connect to upstream proxy");
        }

        socks5_greet_and_authenticate(proxySocketFd);
        relayAddress = socks5_request_tunnel(proxySocketFd, 3 /*UDP ASSOCIATE*/);

        // Establish connection to relay server
        relaySocketFd = socket(AF_INET, SOCK_DGRAM, 0);
        relaySocketFdCleaner = Cleaner([this] {
                close(this->relaySocketFd);
            });

        if (connect(relaySocketFd, (struct sockaddr*)&relayAddress, sizeof(relayAddress)) < 0) {
            throw std::runtime_error("could not connect to udp relay server");
        }
    }

    std::vector<int> get_incoming_sockets() override {
        return std::vector<int>{relaySocketFd};
    }

    void check_socket(int fd) override {
        if (fd != relaySocketFd) {
            throw std::runtime_error("checking incorrect socket");
        }

        struct sockaddr_in fromAddress;
        socklen_t fromAddressLen = sizeof(struct sockaddr_in);
        char buffer[65536] = {};
        char* readPtr = buffer;
        ssize_t recvLen = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddress, &fromAddressLen);
        char* endPtr = buffer + recvLen;

        if (std::memcmp(&fromAddress, &relayAddress, sizeof(struct sockaddr_in)) != 0) {
            std::cerr << "received non-proxy packet on upstream port" << std::endl;
            return;
        }

        std::cerr << "\t" << "RECEIVE DOWN DGRAM   " << clientHost << ":" << clientPort << " <- " << targetHost << ":" << targetPort << std::endl;

        if (recvLen < 4) {
            throw std::runtime_error("SOCKS UDP packet too small");
        }

        readPtr += 2; // Reserved bytes

        if (*((uint8_t*)readPtr) != 0) {
            std::cerr << "\t" << "(DROP)  DOWN DGRAM   " << clientHost << ":" << clientPort << " <x " << targetHost << ":" << targetPort << std::endl;
            return;
        }
        readPtr += 1;

        uint8_t addressType = *((uint8_t*)readPtr);
        readPtr += 1;

        struct sockaddr_in dstAddress = {};
        dstAddress.sin_family = AF_INET;

        switch (addressType) {
        case 1:
            {
                if (readPtr + 4 > endPtr) {
                    throw std::runtime_error("SOCKS UDP packet too small for address");
                }
                dstAddress.sin_addr.s_addr = *((uint32_t*)readPtr); // Preserve network byte order.
                readPtr += 4;
                break;
            }
        case 3:
            {
                if (readPtr + 1 > endPtr) {
                    throw std::runtime_error("SOCKS UDP packet too small for address");
                }
                uint8_t len = *((uint8_t*)readPtr);
                readPtr += 1;
                if (len == 0) {
                    throw std::runtime_error("upstream proxy sent zero-length domain");
                }
                if (readPtr + len > endPtr) {
                    throw std::runtime_error("SOCKS UDP packet too small for address");
                }
                char addressData[256] = {};
                std::memcpy(addressData, readPtr, len);
                readPtr += len;
                addressData[len] = 0; // null terminate
                struct hostent *server = gethostbyname(addressData); // replace with getaddrinfo() later
                if (server == nullptr) {
                    throw std::runtime_error("cannot resolve address returned by upstream proxy");
                }
                if (server->h_addrtype != AF_INET) {
                    throw std::runtime_error("FIXME: Resolved to IPv6 address. Use getaddrinfo() instead.");
                }
                std::memcpy(&dstAddress.sin_addr.s_addr, (char*)server->h_addr, server->h_length);
            }
            break;
        case 4:
            throw std::runtime_error("upstream proxy returned IPv6 address (unsupported)");
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
        dstAddress.sin_port = *((uint16_t*)readPtr);
        readPtr += 2;

        if (std::memcmp(&dstAddress, &targetAddress, sizeof(struct sockaddr_in)) != 0) {
            char dstHostCStr[256] = {};
            inet_ntop(AF_INET, &dstAddress.sin_addr, dstHostCStr, sizeof(dstHostCStr));
            std::string dstHost = std::string(dstHostCStr);
            int dstPort = ntohs(dstAddress.sin_port);
            std::cerr << "SOCKS returned UDP packet from unexpected address and port: " << dstHost << ":" << dstPort << std::endl;
            return;
        }

        send_to_client(readPtr, endPtr - readPtr);
    }

    void send_to_target(const char* buffer, size_t len) override {
        char packet[65536];
        size_t packetLen;
        if (len > MAXIMUM_IPV4_UDP_PAYLOAD) {
            // I would have probably supported fragmentation, but I
            // couldn't find any suitable SOCKS5 servers to use as a
            // test platform.
            //
            // This also raises the question of whether fragmentation
            // is even useful if no one seems to implement it anyway!
            std::cerr << "\t" << "(DROP)  UP   DGRAM   " << clientHost << ":" << clientPort << " x> " << targetHost << ":" << targetPort << std::endl;
            return;
        }
        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, "\x00\x00", sizeof(uint16_t)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, "\x00", sizeof(uint8_t)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, "\x01", sizeof(uint8_t)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_addr.s_addr, sizeof(uint32_t)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_port, sizeof(uint16_t)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, buffer, len) < 0
            || sendto(relaySocketFd, packet, packetLen, 0, (struct sockaddr*)&relayAddress, sizeof(relayAddress)) != ssize_t(packetLen)
            ) {
            throw std::runtime_error("Could not build and send packet to relay server");
        }

        std::cerr << "\t" << "SEND    UP   DGRAM   " << clientHost << ":" << clientPort << " -> " << targetHost << ":" << targetPort << std::endl;
    }
};

#endif
