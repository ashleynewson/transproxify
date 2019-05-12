#ifndef HGUARD_TCP_SERVER
#define HGUARD_TCP_SERVER

#include "ProxySettings.hpp"
#include "Proxy.hpp"
#include "DirectTcpProxy.hpp"
#include "HttpTcpProxy.hpp"
#include "Socks4TcpProxy.hpp"
#include "Socks5TcpProxy.hpp"

class TcpServer {
private:
    ProxySettings proxySettings;
    int listenPort;

public:
    TcpServer(ProxySettings proxySettings, int listenPort):
        proxySettings(proxySettings),
        listenPort(listenPort)
    {
    }

    ~TcpServer() {
    }

    static struct sockaddr_in get_client_address(int clientSocketFd) {
        struct sockaddr_in clientAddress = {};
        socklen_t clientAddressLength = sizeof(clientAddress); // ???
        if (getpeername(clientSocketFd,
                        (struct sockaddr*)&clientAddress,
                        &clientAddressLength
                        ) < 0) {
            close(clientSocketFd);
            exit(1);
        }
        return clientAddress;
    }
    static struct sockaddr_in get_target_address(int clientSocketFd) {
        struct sockaddr_in targetAddress = {};
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
        return targetAddress;
    }

    void run() {
        int listeningSocketFd(socket(AF_INET, SOCK_STREAM, 0));
        if (listeningSocketFd < 0) {
            throw std::runtime_error("could not open server socket");
        }
        Cleaner listeningSocketFdCleaner([&listeningSocketFd] {
                close(listeningSocketFd);
            });

        struct sockaddr_in serverAddress = {};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(listenPort);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        if (bind(listeningSocketFd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
            throw std::runtime_error("could not bind to address and port");
        }
        listen(listeningSocketFd, 5);
        std::cerr << "Listening on " << listenPort << std::endl;

        signal(SIGCHLD, SIG_IGN);
        pid_t parent_pid = getpid();
        while (1) {
            struct sockaddr_in clientAddress = {};
            socklen_t clientAddressLength = sizeof(clientAddress); // ???
            int acceptedSocketFd = accept(listeningSocketFd,
                                          (struct sockaddr*)&clientAddress,
                                          &clientAddressLength);
            if (acceptedSocketFd < 0) {
                perror("error");
                std::cerr << "Error during accept." << std::endl;
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                std::cerr << "Unable to fork new connection handler process! Aborting connection." << std::endl;
                close(acceptedSocketFd);
            }
            else if (pid == 0) {
                // Child!

                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
                    std::cerr << "Could not tie lifetime to parent lifetime" << std::endl;
                    exit(1);
                }
                if (getppid() != parent_pid) {
                    // We seem to have outlived out parent already.
                    exit(1);
                }

                close(listeningSocketFd); // Child doesn't need this.

                struct sockaddr_in connectedServerAddress = get_target_address(acceptedSocketFd);
                struct sockaddr_in connectedClientAddress = get_client_address(acceptedSocketFd);

                char clientHost[256] = {};
                inet_ntop(AF_INET, &connectedClientAddress.sin_addr, clientHost, sizeof(clientHost));

                char connectHost[256] = {};
                inet_ntop(AF_INET, &connectedServerAddress.sin_addr, connectHost, sizeof(connectHost));
                int connectPort = ntohs(connectedServerAddress.sin_port);
                std::cerr << getpid() << "\t" << "Connect " << clientHost << " -> " << connectHost << ":" << connectPort << std::endl;

                try {
                    switch (proxySettings.proxyProtocol) {
                    case ProxySettings::ProxyProtocol::DIRECT:
                    case ProxySettings::ProxyProtocol::REDIRECT:
                        DirectTcpProxy(proxySettings, connectedClientAddress, connectedServerAddress, acceptedSocketFd).run();
                        break;
                    case ProxySettings::ProxyProtocol::HTTP:
                        HttpTcpProxy(proxySettings, connectedClientAddress, connectedServerAddress, acceptedSocketFd).run();
                        break;
                    case ProxySettings::ProxyProtocol::SOCKS4:
                        Socks4TcpProxy(proxySettings, connectedClientAddress, connectedServerAddress, acceptedSocketFd).run();
                        break;
                    case ProxySettings::ProxyProtocol::SOCKS5:
                        Socks5TcpProxy(proxySettings, connectedClientAddress, connectedServerAddress, acceptedSocketFd).run();
                        break;
                    default:
                        throw std::runtime_error("Cannot make unknown proxy type");
                    }
                } catch (const std::exception& e) {
                    std::cerr << getpid() << "\t" << "Error: " << e.what() << std::endl;
                }
                // Reset the connection (well, try)
                connectedServerAddress.sin_family = AF_UNSPEC;
                connect(acceptedSocketFd, (struct sockaddr*)&connectedServerAddress, sizeof(connectedServerAddress));
                close(acceptedSocketFd);
                std::cerr << getpid() << "\t" << "Close   " << clientHost << " -> " << connectHost << ":" << connectPort << std::endl;
                exit(0);
            } else {
                close(acceptedSocketFd); // Parent doesn't need this (anymore).
            }
        }
    }
};

#endif
