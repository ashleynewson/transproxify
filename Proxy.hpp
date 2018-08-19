#ifndef HGUARD_PROXY
#define HGUARD_PROXY

#include <cassert>

#include "Util.hpp"
#include "Cleaner.hpp"
#include "ProxySettings.hpp"

class Proxy {
protected:
    ProxySettings settings;
    struct sockaddr_in clientAddress;
    std::string clientHost;
    int clientPort;
    struct sockaddr_in targetAddress;
    std::string targetHost;
    int targetPort;

public:
    // clientSocketFd becomes owned by Proxy
    Proxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress):
        settings(settings),
        clientAddress(clientAddress),
        targetAddress(targetAddress)
    {
        char clientHostCStr[256] = {};
        inet_ntop(AF_INET, &clientAddress.sin_addr, clientHostCStr, sizeof(clientHost));
        clientHost = std::string(clientHostCStr);
        clientPort = ntohs(clientAddress.sin_port);

        char targetHostCStr[256] = {};
        inet_ntop(AF_INET, &targetAddress.sin_addr, targetHostCStr, sizeof(targetHost));
        targetHost = std::string(targetHostCStr);
        targetPort = ntohs(targetAddress.sin_port);
    }

    virtual ~Proxy() {
    }
};

#endif
