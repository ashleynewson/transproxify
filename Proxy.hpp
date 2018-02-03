#ifndef HGUARD_PROXY
#define HGUARD_PROXY

#include "Util.hpp"
#include "Cleaner.hpp"
#include "ProxySettings.hpp"

class Proxy {
private:
    ProxySettings settings;
    int clientSocketFd;
    std::string clientHost;
    struct sockaddr_in targetAddress;
    std::string targetHost;
    int targetPort;

public:
    // clientSocketFd becomes owned by Proxy
    Proxy(ProxySettings settings, int clientSocketFd, const std::string& clientHost, const struct sockaddr_in& targetAddress):
        settings(settings),
        clientSocketFd(clientSocketFd),
        clientHost(clientHost),
        targetAddress(targetAddress)
    {
        char targetHostCstr[256] = {};
        inet_ntop(AF_INET, &targetAddress.sin_addr, targetHostCstr, sizeof(targetHostCstr));
        targetHost = targetHostCstr;
        targetPort = ntohs(targetAddress.sin_port);
    }

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

    void http_connect(int proxySocketFd) {
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

    void socks4_connect(int proxySocketFd) {
#pragma pack(push, 1)
        struct Socks4Packet {
            uint8_t version;
            uint8_t command; // or response
            uint16_t dest_port;
            uint32_t dest_address;
        };
#pragma pack(pop)

        char packet[65536] = {};
        size_t packetLen = 0;

        Socks4Packet request = {4, 1, targetAddress.sin_port, targetAddress.sin_addr.s_addr};

        const char* userId;
        size_t userIdLen;
        if (!settings.username.empty()) {
            userId = settings.username.c_str();
        } else if (!settings.password.empty()) {
            userId = settings.password.c_str();
        } else {
            userId = "";
        }
        userIdLen = strlen(userId)+1;

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request, sizeof(request)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, userId, userIdLen) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        Socks4Packet response = {};

        if (read_exactly(proxySocketFd, &response, sizeof(response)) != sizeof(response)) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }

        if (response.version != 0) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        switch (response.command) {
        case 90:
            // Success!
            break;
        case 91:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        case 92:
        case 93:
            throw std::runtime_error("upstream proxy identd authentication failure");
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
    };

    void socks5_connect(int proxySocketFd) {
#pragma pack(push, 1)
        struct Socks5Packet1 {
            uint8_t version;
            uint8_t method_count;
        };
        struct Socks5Packet2 {
            uint8_t version;
            uint8_t method;
        };
        struct Socks5Packet3 {
            uint8_t version;
            uint8_t command;
            uint8_t reserved;
            uint8_t address_type; // Must be 1 for our purposes.
        };
#pragma pack(pop)

        char packet[65536] = {};
        size_t packetLen = 0;

        std::vector<uint8_t> methods;
        methods.emplace_back(0x00);
        if (!settings.username.empty()) {
            methods.emplace_back(0x02);
        }

        Socks5Packet1 request1 = {5, uint8_t(methods.size())};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request1, sizeof(request1)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, methods.data(), sizeof(uint8_t) * methods.size()) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during auth negotiation");
        }

        Socks5Packet2 response1 = {};

        if (read_exactly(proxySocketFd, &response1, sizeof(response1)) != sizeof(response1)) {
            throw std::runtime_error("read from upstream proxy failed during auth negotiation");
        }

        if (response1.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }
        switch (response1.method) {
        case 0x00:
            break;
        case 0x02:
            if (settings.username.empty()) {
                // Protocol mismatch?
                throw std::runtime_error("upstream proxy selected username and password authentication where no authentication was expected");
            }
            {
                uint8_t version = 1;
                // Lengths already checked in ProxySettings
                uint8_t usernameLen = settings.username.length();
                const char* username = settings.username.c_str();
                uint8_t passwordLen = settings.password.length();
                const char* password = settings.password.c_str();

                packetLen = 0;
                if (build_packet(packet, sizeof(packet), &packetLen, &version, sizeof(version)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, &usernameLen, sizeof(usernameLen)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, username, usernameLen) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, &passwordLen, sizeof(passwordLen)) < 0
                    || build_packet(packet, sizeof(packet), &packetLen, password, passwordLen) < 0
                    || write_exactly(proxySocketFd, packet, packetLen) < 0
                    )
                {
                    throw std::runtime_error("write to upstream proxy failed during authentication");
                }
                if (read_exactly(proxySocketFd, &version, sizeof(version)) != sizeof(version)) {
                    throw std::runtime_error("read from upstream proxy failed during authentication");
                }
                if (version != 1) {
                    throw std::runtime_error("upstream proxy protocol mismatch");
                }
                uint8_t status = 0;
                if (read_exactly(proxySocketFd, &status, sizeof(status)) != sizeof(status)) {
                    throw std::runtime_error("read from upstream proxy failed during authentication");
                }
                if (status != 0) {
                    throw std::runtime_error("upstream proxy authentication failure");
                }
            }
            break;
        case 0xff:
            throw std::runtime_error("upstream proxy no authentication method");
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        Socks5Packet3 request2 = {5, 1, 0, 1};

        packetLen = 0;
        if (build_packet(packet, sizeof(packet), &packetLen, &request2, sizeof(request2)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_addr.s_addr, sizeof(targetAddress.sin_addr.s_addr)) < 0
            || build_packet(packet, sizeof(packet), &packetLen, &targetAddress.sin_port, sizeof(targetAddress.sin_port)) < 0
            || write_exactly(proxySocketFd, packet, packetLen) < 0
            )
        {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        Socks5Packet3 response2 = {};

        if (read_exactly(proxySocketFd, &response2, sizeof(response2)) != sizeof(response2)) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }

        if (response2.version != 5) {
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        switch (response2.command) {
        case 0:
            // Success!
            break;
        case 2:
            throw std::runtime_error("upstream proxy rejected connection not allowed by ruleset");
        default:
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint or rejected connection");
        }

        char discard[256] = {};
        switch (response2.address_type) {
        case 1:
            if (read_exactly(proxySocketFd, &discard, 4) != sizeof(response2)) {
                throw std::runtime_error("read from upstream proxy failed during CONNECT");
            }
            break;
        case 3:
            {
                uint8_t len;
                if (read_exactly(proxySocketFd, &len, sizeof(len)) != sizeof(len)) {
                    throw std::runtime_error("read from upstream proxy failed during CONNECT");
                }
                if (len == 0) {
                    throw std::runtime_error("upstream proxy sent zero-length domain");
                }
                if (read_exactly(proxySocketFd, &discard, len) != len) {
                    throw std::runtime_error("read from upstream proxy failed during CONNECT");
                }
            }
            break;
        case 4:
            if (read_exactly(proxySocketFd, &discard, 16) != 16) {
                throw std::runtime_error("read from upstream proxy failed during CONNECT");
            }
            break;
        default:
            throw std::runtime_error("upstream proxy protocol mismatch");
        }

        if (read_exactly(proxySocketFd, &discard, 2) != 2) {
            throw std::runtime_error("read from upstream proxy failed during CONNECT");
        }
    };

    void run() {
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

        switch (settings.proxyProtocol) {
        case ProxySettings::ProxyProtocol::HTTP:
            http_connect(proxySocketFd);
            break;
        case ProxySettings::ProxyProtocol::SOCKS4:
            socks4_connect(proxySocketFd);
            break;
        case ProxySettings::ProxyProtocol::SOCKS5:
            socks5_connect(proxySocketFd);
            break;
        default:
            throw std::runtime_error("invalid proxy protocol");
        }

        // We're finally tunnling proper data!
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
};

#endif
