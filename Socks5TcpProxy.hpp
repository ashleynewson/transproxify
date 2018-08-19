#ifndef HGUARD_SOCKS5_TCP_PROXY
#define HGUARD_SOCKS5_TCP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "TcpProxy.hpp"
#include "Socks5Proxy.hpp"

class Socks5TcpProxy : public TcpProxy, public Socks5Proxy {
public:
    Socks5TcpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress, int clientSocketFd):
        Proxy(settings, clientAddress, targetAddress),
        TcpProxy(settings, clientAddress, targetAddress, clientSocketFd),
        Socks5Proxy(settings, clientAddress, targetAddress)
    {
    }

private:
    void proxy_negotiate(int proxySocketFd) {
        socks5_greet_and_authenticate(proxySocketFd);
        socks5_request_tunnel(proxySocketFd, 1 /*CONNECT*/);
    }
};

#endif
