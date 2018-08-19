#ifndef HGUARD_DIRECT_UDP_PROXY
#define HGUARD_DIRECT_UDP_PROXY

#include <cstring>
#include "UdpProxy.hpp"

class DirectUdpProxy : public UdpProxy {
private:
    int targetSocketFd;
    int proxyPort;
    Cleaner targetSocketFdCleaner;
public:
    DirectUdpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress):
        UdpProxy(settings, clientAddress, targetAddress)
    {
        // to client
        targetSocketFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (targetSocketFd < 0) {
            std::cerr << "cannot open socket for sending to client" << std::endl;
            return;
        }
        targetSocketFdCleaner = Cleaner([this] {
                close(this->targetSocketFd);
            });
        struct sockaddr_in serverAddress = {};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(0);
        serverAddress.sin_addr.s_addr = INADDR_ANY;
        // Binding essentially assigns us an address/port for receiving replies.
        // Might not be entirely necessary, however, due to auto-binding.
        if (bind(targetSocketFd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
            throw std::runtime_error("could not bind to address and port for sending to target");
        }
        // Set the default address/port for sending packets.
        if (connect(targetSocketFd, (struct sockaddr*)&targetAddress, sizeof(targetAddress)) < 0) {
            throw std::runtime_error("could not connect for sending to target");
        }
    }

    std::vector<int> get_incoming_sockets() override {
        return std::vector<int>{targetSocketFd};
    }

    void check_socket(int fd) override {
        if (fd != targetSocketFd) {
            throw std::runtime_error("checking incorrect socket");
        }

        struct sockaddr_in fromAddress;
        socklen_t fromAddressLen = sizeof(struct sockaddr_in);
        char buffer[65536] = {};
        ssize_t recvLen = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddress, &fromAddressLen);

        if (std::memcmp(&fromAddress, &targetAddress, sizeof(struct sockaddr_in)) != 0) {
            std::cerr << "received non-proxy packet on upstream port" << std::endl;
            return;
        }

        std::cerr << "\t" << "RECEIVE DOWN DGRAM   " << clientHost << ":" << clientPort << " <- " << targetHost << ":" << targetPort << std::endl;

        send_to_client(buffer, recvLen);
    }

    void send_to_target(const char* buffer, size_t len) override {
        if (sendto(targetSocketFd, buffer, len, 0, (struct sockaddr*)&targetAddress, sizeof(targetAddress)) != (ssize_t)len) {
            perror("sendto failed sending to target");
            std::cerr << "\t" << "FAILED SEND DGRAM   " << clientHost << ":" << clientPort << " -> " << targetHost << ":" << targetPort << std::endl;
            return;
        }

        std::cerr << "\t" << "SEND    UP   DGRAM   " << clientHost << ":" << clientPort << " -> " << targetHost << ":" << targetPort << std::endl;
    }
};

#endif
