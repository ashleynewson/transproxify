#ifndef HGUARD_TCP_PROXY
#define HGUARD_TCP_PROXY

#include <unistd.h>

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "Proxy.hpp"

class TcpProxy : public Proxy {
protected:
    int clientSocketFd;
    struct sockaddr_in clientAddress;
    std::string clientHost;
    struct sockaddr_in targetAddress;
    std::string targetHost;
    int targetPort;

    TcpProxy(ProxySettings settings, int clientSocketFd):
        Proxy(settings),
        clientSocketFd(clientSocketFd)
    {
        targetAddress = {};
        socklen_t targetAddressLength = sizeof(targetAddress); // ???
        if (getsockopt(clientSocketFd,
                       SOL_IP,
                       SO_ORIGINAL_DST,
                       (struct sockaddr*)&targetAddress,
                       &targetAddressLength
                       ) < 0) {
#ifdef ALLOW_DIRECT_CONNECTIONS
            // Useful for debugging.
            if (getsockname(clientSocketFd,
                            (struct sockaddr*)&targetAddress,
                            &targetAddressLength
                            ) < 0) {
                close(clientSocketFd);
                exit(1);
            }
#else
            close(clientSocketFd);
            exit(1);
#endif
        }

        char targetHostCstr[256] = {};
        inet_ntop(AF_INET, &targetAddress.sin_addr, targetHostCstr, sizeof(targetHostCstr));
        targetHost = targetHostCstr;
        targetPort = ntohs(targetAddress.sin_port);

        struct sockaddr_in clientAddress = {};
        socklen_t clientAddressLength = sizeof(clientAddress); // ???
        if (getpeername(clientSocketFd,
                        (struct sockaddr*)&clientAddress,
                        &clientAddressLength
                        ) < 0) {
            close(clientSocketFd);
            exit(1);
        }

        char clientHost[256] = {};
        inet_ntop(AF_INET, &clientAddress.sin_addr, clientHost, sizeof(clientHost));
    }

    virtual ~TcpProxy() {
    }

    virtual void proxy_negotiate(int proxySocketFd) = 0;

    virtual void relay(int proxySocketFd) {
        std::cerr << getpid() << "\t" << "Tunnel  " << clientHost << " -> " << targetHost << ":" << targetPort << std::endl;

        char data[65536] = {};
        int data_len = 0;
        bool clientOpen = true;
        bool proxyOpen = true;
        while (clientOpen || proxyOpen) {
            struct pollfd fds[] = {
                { clientSocketFd, short(clientOpen ? (POLLIN | POLLHUP) : -1), 0 },
                { proxySocketFd, short(proxyOpen ? (POLLIN | POLLHUP) : -1), 0 },
            };
            if (poll(fds, 2, -1) < 0) {
                throw std::runtime_error("poll error whilst proxying");
            } else {
                if (clientOpen && fds[0].revents & (POLLIN | POLLHUP)) {
                    data_len = read(clientSocketFd, data, sizeof(data));
                    if (data_len < 0) {
                        throw std::runtime_error("client read error");
                    }
                    if (data_len == 0) {
                        clientOpen = false;
                        std::cerr << getpid() << "\t" << "CliHUP  " << clientHost << " -> " << targetHost << ":" << targetPort << std::endl;
                        shutdown(proxySocketFd, SHUT_WR);
                    } else {
                        if (write_exactly(proxySocketFd, data, data_len) < 0) {
                            throw std::runtime_error("upstream proxy write error");
                        }
                    }
                }
                if (proxyOpen && fds[1].revents & (POLLIN | POLLHUP)) {
                    data_len = read(proxySocketFd, data, sizeof(data));
                    if (data_len < 0) {
                        throw std::runtime_error("upstream proxy read error");
                    }
                    if (data_len == 0) {
                        proxyOpen = false;
                        std::cerr << getpid() << "\t" << "ProHUP  " << clientHost << " -> " << targetHost << ":" << targetPort << std::endl;
                        shutdown(clientSocketFd, SHUT_WR);
                    } else {
                        if (write_exactly(clientSocketFd, data, data_len) < 0) {
                            throw std::runtime_error("client write error");
                        }
                    }
                }
            }
        }
    }

public:
    virtual void run() {
        // We will be finished with the client whenever this method
        // finishes.
        Cleaner clientSocketFdCleaner([this] {
                close(this->clientSocketFd);
            });

        // Establish connection to proxy
        int proxySocketFd = socket(AF_INET, SOCK_STREAM, 0);
        Cleaner proxySocketFdCleaner([&proxySocketFd] {
                close(proxySocketFd);
            });

        if (connect(proxySocketFd, (struct sockaddr*)&settings.proxyAddress, sizeof(settings.proxyAddress)) < 0) {
            throw std::runtime_error("could not connect to upstream proxy");
        }

        proxy_negotiate(proxySocketFd);

        relay(proxySocketFd);
    }
};

#endif
