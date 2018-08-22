#ifndef HGUARD_DIRECT_TCP_PROXY
#define HGUARD_DIRECT_TCP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "TcpProxy.hpp"

class DirectTcpProxy : public TcpProxy {
public:
    DirectTcpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress, int clientSocketFd):
        Proxy(settings, clientAddress, targetAddress),
        TcpProxy(settings, clientAddress, targetAddress, clientSocketFd)
    {
    }

    void run() override {
        // We will be finished with the client whenever this method
        // finishes.
        Cleaner clientSocketFdCleaner([this] {
                close(this->clientSocketFd);
            });

        // Establish connection to proxy
        int targetSocketFd = socket(AF_INET, SOCK_STREAM, 0);
        Cleaner targetSocketFdCleaner([&targetSocketFd] {
                close(targetSocketFd);
            });

        if (connect(targetSocketFd, (struct sockaddr*)&targetAddress, sizeof(targetAddress)) < 0) {
            throw std::runtime_error("could not connect to target");
        }

        relay(targetSocketFd);
    }
};

#endif
