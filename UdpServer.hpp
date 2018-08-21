#ifndef HGUARD_UDP_SERVER
#define HGUARD_UDP_SERVER

#include <unistd.h>

#include "ProxySettings.hpp"
#include "Proxy.hpp"
#include "UdpProxy.hpp"
#include "DirectUdpProxy.hpp"
#include "Socks5UdpProxy.hpp"



#define UDP_PROXY_LIMIT 256



class UdpServer {
private:
    ProxySettings proxySettings;
    int bindPort;

    /// Maps internal address:port and external address:port to re-mapped port.
    /// E.g.:
    ///  <192.168.1.123, 55555, 8.8.8.8, 53>, 44444
    ///  for a NAT-ing of
    ///  192.168.1.123:55555 <-> "8.8.8.8:53"/proxy:44444 <-> 8.8.8.8:53
    std::map<std::tuple<unsigned long, short, unsigned long, short>, short> toMappedPort;
    /// Maps external address:port and re-mapped port to internal address:port.
    /// E.g.:
    ///  <8.8.8.8, 53, 44444>, <192.168.1.123, 55555>
    ///  for a NAT-ing of
    ///  192.168.1.123:55555 <-> "8.8.8.8:53"/proxy:44444 <-> 8.8.8.8:53
    std::map<std::tuple<unsigned long, short, short>, std::tuple<unsigned long, short>> fromMappedPort;

    /// Maps internal address:port and external address:port to proxy.
    /// E.g.:
    ///  <192.168.1.123, 55555, 8.8.8.8, 53>, proxy_44444
    ///  for a NAT-ing of
    ///  192.168.1.123:55555 <-> "8.8.8.8:53"/proxy:44444 <-> 8.8.8.8:53
    std::map<std::tuple<unsigned long, short, unsigned long, short>, std::shared_ptr<UdpProxy>> proxies;


    std::map<short, int> portToSocket;
    std::map<int, std::shared_ptr<UdpProxy>> socketToProxy;

    std::shared_ptr<UdpProxy> evict_proxy() {
        int score = INT_MIN;
        std::shared_ptr<UdpProxy> victim;
        for (auto it = proxies.begin(); it != proxies.end(); it++) {
            const std::shared_ptr<UdpProxy>& proxy = it->second;
            int thisScore = proxy->eviction_score();
            if (thisScore > score) {
                score = thisScore;
                victim = proxy;
            }
        }
        if (victim) {
            delete_proxy(victim);
        }
        return victim;
    }

    int clean_proxies() {
        int count = 0;
        for (auto it = proxies.begin(); it != proxies.end(); it++) {
            const std::shared_ptr<UdpProxy>& proxy = it->second;
            if (proxy->timed_out()) {
                count++;
                delete_proxy(proxy);
            }
        }
        return count;
    }

    void delete_proxy(std::shared_ptr<UdpProxy> proxy) {
        std::tuple<unsigned long, short, unsigned long, short> key = std::make_tuple<unsigned long, short, unsigned long, short>(proxy->clientAddress.sin_addr.s_addr, proxy->clientAddress.sin_port, proxy->targetAddress.sin_addr.s_addr, proxy->targetAddress.sin_port);

        proxies.erase(key);

        for (const int& socket : proxy->get_incoming_sockets()) {
            socketToProxy.erase(socket);
        }
    }

    std::shared_ptr<UdpProxy> new_proxy(struct sockaddr_in clientAddress, struct sockaddr_in targetAddress) {
        std::shared_ptr<UdpProxy> proxy;

        if (proxies.size() >= UDP_PROXY_LIMIT) {
            evict_proxy();
        }

        switch (proxySettings.proxyProtocol) {
        case ProxySettings::ProxyProtocol::DIRECT:
            proxy = std::make_shared<DirectUdpProxy>(proxySettings, clientAddress, targetAddress);
            break;
        case ProxySettings::ProxyProtocol::SOCKS5:
            proxy = std::make_shared<Socks5UdpProxy>(proxySettings, clientAddress, targetAddress);
            break;
        default:
            throw std::runtime_error("invalid proxy protocol");
        }

        std::tuple<unsigned long, unsigned short, unsigned long, unsigned short> index = std::make_tuple(clientAddress.sin_addr.s_addr, clientAddress.sin_port, targetAddress.sin_addr.s_addr, targetAddress.sin_port);
        proxies.emplace(index, proxy);

        for (const int& socket : proxy->get_incoming_sockets()) {
            socketToProxy.emplace(socket, proxy);
        }

        return proxy;
    }

    void send(sockaddr_in source, sockaddr_in destination, char* data, size_t len) {
        std::tuple<unsigned long, short, unsigned long, short> index = std::make_tuple(source.sin_addr.s_addr, source.sin_port, destination.sin_addr.s_addr, destination.sin_port);

        auto lookup = proxies.find(index);
        std::shared_ptr<UdpProxy> proxy;
        try {
            if (lookup == proxies.end()) {
                proxy = new_proxy(source, destination);
            } else {
                proxy = lookup->second;
            }

            proxy->send_to_target(data, len);
        } catch (const std::exception& e) {
            std::cerr << "\t" << "Error: " << e.what() << std::endl;
        }
    }

    void recv(int fd) {
        // Dodge:
        auto it = socketToProxy.find(fd);
        if (it == socketToProxy.end()) {
            throw std::runtime_error("attempt to use non-proxy socket");
        }
        UdpProxy& proxy = *(it->second);

        try {
            proxy.check_socket(fd);
        } catch (const std::exception& e) {
            std::cerr << "\t" << "Error: " << e.what() << std::endl;
        }
    }

public:
    UdpServer(ProxySettings proxySettings, int bindPort):
        proxySettings(proxySettings),
        bindPort(bindPort)
    {
    }

    ~UdpServer() {
    }

    void run() {
        int bindSocketFd(socket(AF_INET, SOCK_DGRAM, 0));
        if (bindSocketFd < 0) {
            throw std::runtime_error("could not open server socket");
        }
        Cleaner bindSocketFdCleaner([&bindSocketFd] {
                close(bindSocketFd);
            });

        struct sockaddr_in serverAddress = {};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(bindPort);
        serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

        const int on = 1;

        if (setsockopt(bindSocketFd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0) {
            throw std::runtime_error("could not set IP_TRANSPARENT");
        }
        if (setsockopt(bindSocketFd, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) < 0) {
            throw std::runtime_error("could not set IP_RECVORIGDSTADDR");
        }

        if (bind(bindSocketFd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
            throw std::runtime_error("could not bind to address and port");
        }
        std::cerr << "Bound on " << bindPort << std::endl;

        char buffer[65536] = {};
        char controlBuffer[512] = {};
        struct sockaddr_in clientAddress = {};
        struct sockaddr_in targetAddress = {};
        struct iovec iov;
        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);
        struct msghdr message;
        message.msg_name=&clientAddress;
        message.msg_namelen=sizeof(clientAddress);
        message.msg_iov=&iov;
        message.msg_iovlen=1;
        message.msg_control=controlBuffer;
        message.msg_controllen=sizeof(controlBuffer);

        while (1) {
            std::vector<struct pollfd> fds;
            fds.push_back({bindSocketFd, POLLIN, 0});
            for (const std::pair<int, std::shared_ptr<UdpProxy>>& p : socketToProxy) {
                fds.push_back({p.first, POLLIN, 0});
            }
            if (poll(fds.data(), fds.size(), 1000) < 0) {
                throw std::runtime_error("poll error whilst proxying");
            }

            for (size_t i = 1; i < fds.size(); i++) {
                if (fds[i].revents & POLLIN) {
                    recv(fds[i].fd);
                }
            }

            if (fds[0].revents & POLLIN) {
                int recv_len = recvmsg(bindSocketFd, &message, 0);

                if (recv_len <= 0) {
                    perror("error");
                    std::cerr << "Error during recvfrom." << std::endl;
                    continue;
                }

                struct cmsghdr *cmsg;
                bool gotOrigAddr = false;
                for (cmsg = CMSG_FIRSTHDR(&message); cmsg;
                     cmsg = CMSG_NXTHDR(&message, cmsg)) {
                    if (cmsg->cmsg_level == SOL_IP) {
                        switch (cmsg->cmsg_type) {
                        case IP_ORIGDSTADDR:
                            targetAddress = *((struct sockaddr_in *)CMSG_DATA(cmsg));
                            gotOrigAddr = true;
                            break;
                        }
                    }
                }
                if (!gotOrigAddr) {
                    std::cerr << "Got direct datagram." << std::endl;
                }

                char clientHost[256] = {};
                inet_ntop(AF_INET, &clientAddress.sin_addr, clientHost, sizeof(clientHost));
                int clientPort = ntohs(clientAddress.sin_port);

                char targetHost[256] = {};
                inet_ntop(AF_INET, &targetAddress.sin_addr, targetHost, sizeof(targetHost));
                int targetPort = ntohs(targetAddress.sin_port);

                std::cerr << "\t" << "RECEIVE UP   DGRAM   " << clientHost << ":" << clientPort << " -> " << targetHost << ":" << targetPort << std::endl;

                send(clientAddress, targetAddress, buffer, recv_len);
            }
        }
    }
};

#endif
