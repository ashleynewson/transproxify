#ifndef HGUARD_PROXY_SETTINGS
#define HGUARD_PROXY_SETTINGS

#include <sys/socket.h>

class Proxy;

struct ProxySettings {
public:
    enum class ProxyProtocol {
        HTTP,
        SOCKS4,
        SOCKS5,
    };
    enum class ProxiedProtocol {
        TCP,
        UDP,
    };
    // template<class ProtocolType>
    // static inline const char* protocol_name(ProtocolType);
    // template<>
    static inline const char* protocol_name(ProxyProtocol protocol) {
        switch (protocol) {
        case ProxyProtocol::HTTP:
            return "HTTP";
        case ProxyProtocol::SOCKS4:
            return "SOCKSv4";
        case ProxyProtocol::SOCKS5:
            return "SOCKSv5";
        default:
            return "Invalid Proxy Protocol";
        }
    }
    // template<>
    static inline const char* protocol_name(ProxiedProtocol protocol) {
        switch (protocol) {
        case ProxiedProtocol::TCP:
            return "TCP";
        case ProxiedProtocol::UDP:
            return "UDP";
        default:
            return "Invalid Proxied Protocol";
        }
    }

public:
    ProxyProtocol proxyProtocol;
    ProxiedProtocol proxiedProtocol;
    std::string username;
    std::string password;
    struct sockaddr_in proxyAddress;

private:
    static inline void check_support(ProxyProtocol proxy, ProxiedProtocol proxied, std::initializer_list<ProxiedProtocol> supportList) {
        for (const ProxiedProtocol& supported : supportList) {
            if (proxied == supported) {
                return;
            }
        }
        throw std::runtime_error(std::string() + protocol_name(proxy) + " does not support proxying " + protocol_name(proxied));
    }

    // template<class Proxy, class Proxied, std::tuple<class... Supported>>
    // struct check_support;
    // template<Proxy, Proxied>
    // struct check_support<Proxy, Proxied, std::tuple<>> {
    //     static void check() {
    //         throw std::runtime_error();
    //     }
    // };
    // template<Proxy, Proxied, SupportedH, std::tuple<class... SupportedT>>
    // struct check_support<Proxy, Proxied, std::tuple<SupportedH, SupportedT...>> {
    //     static void check() {
    //         if (std::is_same<Proxied, SupportedH>) {
    //             return; // Found a match!
    //         }
    //         check_support<Proxy, Proxied, std::tuple<SupportedT...>>::check();
    //     }
    // }

public:
    ProxySettings(ProxyProtocol proxyProtocol,
                  ProxiedProtocol proxiedProtocol,
                  const std::string& proxyHost,
                  int proxyPort,
                  const std::string& username,
                  const std::string& password
                  ):
        proxyProtocol(proxyProtocol),
        proxiedProtocol(proxiedProtocol),
        username(username),
        password(password)
    {
        struct hostent *server = gethostbyname(proxyHost.c_str()); // replace with getaddrinfo() later
        if (server == nullptr) {
            throw std::runtime_error("could not resolve proxy hostname");
        }
        proxyAddress = {};
        proxyAddress.sin_family = AF_INET;
        bcopy((char*)server->h_addr, &proxyAddress.sin_addr.s_addr, server->h_length);
        proxyAddress.sin_port = htons(proxyPort);

        switch (proxyProtocol) {
        case ProxyProtocol::HTTP:
            check_support(ProxyProtocol::HTTP, proxiedProtocol, {ProxiedProtocol::TCP});
            if (username.empty() != password.empty()) {
                throw std::runtime_error("got only one of username or password for HTTP");
            }
            if (!username.empty() && username.find(':') != std::string::npos) {
                throw std::runtime_error("HTTP username cannot contain ':' character");
            }
            break;
        case ProxyProtocol::SOCKS4:
            check_support(ProxyProtocol::SOCKS4, proxiedProtocol, {ProxiedProtocol::TCP});
            if (!username.empty() && !password.empty()) {
                throw std::runtime_error("need only one of username or password for SOCKS4");
            }
            break;
        case ProxyProtocol::SOCKS5:
            check_support(ProxyProtocol::SOCKS5, proxiedProtocol, {ProxiedProtocol::TCP, ProxiedProtocol::UDP});
            if (username.empty() != password.empty()) {
                throw std::runtime_error("got only one of username or password for SOCKS5");
            }
            if (username.size() > 255) {
                throw std::runtime_error("username too long for SOCKS5");
            }
            if (password.size() > 255) {
                throw std::runtime_error("password too long for SOCKS5");
            }
            break;
        default:
            throw std::runtime_error("bad protocol setting");
        }
    }
};

#endif
