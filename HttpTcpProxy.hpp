#ifndef HGUARD_HTTP_TCP_PROXY
#define HGUARD_HTTP_TCP_PROXY

#include "Util.hpp"
#include "ProxySettings.hpp"
#include "TcpProxy.hpp"

class HttpTcpProxy : public TcpProxy {
public:
    HttpTcpProxy(ProxySettings settings, struct sockaddr_in clientAddress, struct sockaddr_in targetAddress, int clientSocketFd):
        Proxy(settings, clientAddress, targetAddress),
        TcpProxy(settings, clientAddress, targetAddress, clientSocketFd)
    {
    }

private:
    int get_http_proxy_status(int proxySocketFd) {
        char line[256] = {};
        size_t i;
        for (i = 0; i < sizeof(line); i++) {
            int c = 0;
            do {
                if (read(proxySocketFd, &c, 1) <= 0) {
                    throw std::runtime_error("upstream proxy connection lost before tunnelling");
                }
            } while (c == '\r'); // F**k carriage return.
            line[i] = c;
            if (c == '\n') {
                line[i] = 0;
                break;
            }
        }
        if (i == sizeof(line)) {
            throw std::runtime_error("upstream proxy response too large");
        }
        std::string str(line);
        std::regex code_regex("^HTTP/1.1 ([0-9]{3}) "); // capitalisation?
        std::smatch match;
        if (!std::regex_search(str, match, code_regex)) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
        int code = std::stoi(match[1]); // This shouldn't ever fail.

        // Exhaust proxy data then return code
        bool newline = true;
        while (true) {
            int c = 0;
            do {
                if (read(proxySocketFd, &c, 1) <= 0) {
                    throw std::runtime_error("upstream proxy connection lost before tunnelling");
                }
            } while (c == '\r'); // F**k carriage return.
            if (c == '\n') {
                if (newline) {
                    // Two newlines in a row means we've reach the endpoint data
                    return code;
                } else {
                    newline = true;
                }
            } else {
                newline = false;
            }
        }
    }

    void proxy_negotiate(int proxySocketFd) {
        std::string tunnelRequest =
            "CONNECT " + targetHost + ":" + std::to_string(targetPort) + " HTTP/1.1\n"
            + "Host: " + targetHost + ":" + std::to_string(targetPort) + "\n"
            + (!settings.username.empty() ? "Proxy-Authorization: Basic " + base64encode(settings.username + ":" + settings.password) + "\n" : "")
            + "\n";

        if (write_exactly(proxySocketFd, tunnelRequest.c_str(), tunnelRequest.length()) < 0) {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        switch (get_http_proxy_status(proxySocketFd)) {
        case 200:
            // All good.
            break;
        case 407:
            throw std::runtime_error("upstream proxy authorization required");
        default:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        }
    };
};

#endif
