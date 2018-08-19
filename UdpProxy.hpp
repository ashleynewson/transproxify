#ifndef HGUARD_UDP_PROXY
#define HGUARD_UDP_PROXY

#include <unistd.h>

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "Proxy.hpp"



#ifndef UDP_PROXY_TIMEOUT
#define UDP_PROXY_TIMEOUT 300
#endif

class UdpServer;



class UdpProxy : public Proxy {
    friend class UdpServer;

protected:
    struct sockaddr_in clientAddress;
    std::string clientHost;
    int clientPort;
    struct sockaddr_in targetAddress;
    std::string targetHost;
    int targetPort;
    short mappedPort;
    time_t startTime;
    time_t lastPacketTime;

public:
    UdpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress):
        Proxy(settings),
        clientAddress(clientAddress),
        targetAddress(targetAddress)
    {
        startTime = time(nullptr);
        lastPacketTime = startTime;

        char clientHostCStr[256] = {};
        inet_ntop(AF_INET, &clientAddress.sin_addr, clientHostCStr, sizeof(clientHost));
        clientHost = std::string(clientHostCStr);
        clientPort = ntohs(clientAddress.sin_port);

        char targetHostCStr[256] = {};
        inet_ntop(AF_INET, &targetAddress.sin_addr, targetHostCStr, sizeof(targetHost));
        targetHost = std::string(targetHostCStr);
        targetPort = ntohs(targetAddress.sin_port);
    }

    virtual ~UdpProxy() {
        std::cerr << "\t" << "DISASSOCIATED        " << clientHost << ":" << clientPort << " -- " << targetHost << ":" << targetPort << std::endl;
    }

    void update_time() {
        lastPacketTime = time(nullptr);
    }

    void send_to_client(char* buffer, size_t len) {
        int sendFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sendFd < 0) {
            std::cerr << "cannot open socket for sending to client" << std::endl;
            return;
        }
        {
            Cleaner sendFdCleaner([sendFd] {
                                      close(sendFd);
                                  });

            const int on = 1;
            if (setsockopt(sendFd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0) {
                throw std::runtime_error("could not set IP_TRANSPARENT for sending to client");
            }
            if (bind(sendFd, (struct sockaddr*)&targetAddress, sizeof(targetAddress)) < 0) {
                perror("bind failed sending to client");
                std::cerr << "\t" << "failed bind: " << targetHost << ":" << targetPort << std::endl;
                throw std::runtime_error("could not bind to address and port for sending to client");
            }

            if (sendto(sendFd, buffer, len, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) != (ssize_t)len) {
                perror("sento failed sending to client");
                std::cerr << "sendto failed sending to client" << std::endl;
                return;
            }
        }

        std::cerr << "\t" << "SEND    DOWN DGRAM   " << clientHost << ":" << clientPort << " <- " << targetHost << ":" << targetPort << std::endl;

        update_time();
    }

    virtual void send_to_target(const char* buffer, size_t len) = 0;

    virtual void check_socket(int fd) = 0;

    virtual std::vector<int> get_incoming_sockets() = 0;

    virtual int eviction_score() {
        int activityBias = lastPacketTime - startTime;
        if (activityBias > 10) {
            activityBias = 10;
        }
        time_t timeNow = time(nullptr);
        return timeNow - lastPacketTime - activityBias;
    }

    virtual bool timed_out() {
        time_t timeNow = time(nullptr);
        return (timeNow - lastPacketTime) > UDP_PROXY_TIMEOUT;
    }
};

#endif
