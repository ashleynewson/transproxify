#include <iostream>
#include <functional>
#include <stdexcept>
#include <string>
#include <cstring>
#include <regex>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <poll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>

void print_usage() {
    const char* usage = R"END_USAGE(Transproxify - Copyright Ashley Newson 2018

Usage:
    transproxify PROXY_HOST PROXY_PORT LISTEN_PORT

Synopsis:
    Perform transparent proxying through an HTTP proxy.

    Not all software supports configuring proxies. With transproxify, you can
    force communications to pass through an HTTP proxy from inside the router.

    Transproxify listens on a given port accepting redirected traffic. When a
    redirected client connects to transproxify, transproxify will connect to a
    given HTTP proxy server and use the CONNECT method to establish a tunnel
    for forwarding data between the client and its intended server.

    Transproxify will not intercept traffic by itself. You may need to alter
    firewall settings. For example, to use transproxify to proxy HTTP and HTTPS
    traffic on ports 80 and 443 via proxyserver:8080, you might use:

      # echo 1 > /proc/sys/net/ipv4/ip_forward
      # iptables -t nat -A PREROUTING -p tcp \
            --match multiport --dports 80,443 \
            -j REDIRECT --to-port 10000
      # transproxify proxyserver 8080 10000

    If your transparent proxying machine isn't already set up to do so, it may 
    also be necessary to forward other ports. A quick (and potentially
    dangerous) way to do this would be using:

      # iptables -A FORWARD -j ACCEPT

    Arp spoofing may also be convenient for certain purposes, such as security
    research from non-router hosts:

      # arpspoof -i NETWORK_INTERFACE -t CLIENT_ADDRESS ROUTER_ADDRESS
)END_USAGE";

    std::cerr << usage;
}

class Cleaner {
private:
    bool enabled;
    std::function<void()> cleaner;
public:
    Cleaner(std::function<void()> cleaner):
        enabled(true),
        cleaner(cleaner)
    {
    }
    ~Cleaner() {
    }
    void disable() {
        enabled = false;
    }
    void clean() {
        if (enabled) {
            cleaner();
            enabled = false;
        }
    }
};

class Proxy;

struct ProxySettings {
private:
    friend class Proxy;
    struct sockaddr_in proxyAddress;
public:
    ProxySettings(const char* proxyHost, int proxyPort) {
        struct hostent *server = gethostbyname(proxyHost); // replace with getaddrinfo() later
        if (server == nullptr) {
            throw std::runtime_error("could not resolve proxy hostname");
        }
        proxyAddress = {};
        proxyAddress.sin_family = AF_INET;
        bcopy((char*)server->h_addr, &proxyAddress.sin_addr.s_addr, server->h_length);
        proxyAddress.sin_port = htons(proxyPort);
    }
};

class Proxy {
private:
    ProxySettings settings;
    int clientSocketFd;
    std::string clientHost;
    std::string targetHost;
    int targetPort;

public:
    // clientSocketFd becomes owned by Proxy
    Proxy(ProxySettings settings, int clientSocketFd, const std::string& clientHost, const std::string& targetHost, int targetPort):
        settings(settings),
        clientSocketFd(clientSocketFd),
        clientHost(clientHost),
        targetHost(targetHost),
        targetPort(targetPort)
    {
    }

    int get_proxy_status(int proxySocketFd) {
        char line[256] = {};
        int i;
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

        std::string tunnelRequest = "CONNECT " + targetHost + ":" + std::to_string(targetPort) + " HTTP/1.1\nHost: " + targetHost + ":" + std::to_string(targetPort) + "\n\n";

        if (write(proxySocketFd, tunnelRequest.c_str(), tunnelRequest.length()) < 0) {
            throw std::runtime_error("write to upstream proxy failed during CONNECT");
        }

        if (get_proxy_status(proxySocketFd) != 200) {
            throw std::runtime_error("upstream proxy failed to establish connection to endpoint");
        }

        // We're finally tunnling proper data!
        std::cerr << "Tunnel  " << clientHost << " -> " << targetHost << ":" << targetPort << " (" << clientSocketFd << ", " << proxySocketFd << ")" << std::endl;

        char data[65536] = {};
        int data_len = 0;
        bool clientOpen = true;
        bool proxyOpen = true;
        while (clientOpen || proxyOpen) {
            struct pollfd fds[] = {
                { clientSocketFd, short(clientOpen ? (POLLIN | POLLHUP) : -1) },
                { proxySocketFd, short(proxyOpen ? (POLLIN | POLLHUP) : -1) },
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
                        std::cerr << "CliHUP  " << clientHost << " -> " << targetHost << ":" << targetPort << " (" << clientSocketFd << ", " << proxySocketFd << ")" << std::endl;
                        shutdown(proxySocketFd, SHUT_WR);
                    } else {
                        if (write(proxySocketFd, data, data_len) < 0) {
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
                        std::cerr << "ProHUP  " << clientHost << " -> " << targetHost << ":" << targetPort << " (" << clientSocketFd << ", " << proxySocketFd << ")" << std::endl;
                        shutdown(clientSocketFd, SHUT_WR);
                    } else {
                        if (write(clientSocketFd, data, data_len) < 0) {
                            throw std::runtime_error("client write error");
                        }
                    }
                }
            }
        }
    }
};

class Server {
private:
    ProxySettings proxySettings;
    int listenPort;

public:
    Server(ProxySettings proxySettings, int listenPort):
        proxySettings(proxySettings),
        listenPort(listenPort)
    {
    }

    ~Server() {
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
                throw std::runtime_error("die");
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                std::cerr << "Unable to fork new connection handler process! Aborting connection." << std::endl;
                close(acceptedSocketFd);
            }
            else if (pid == 0) {
                // Child!

                int r = prctl(PR_SET_PDEATHSIG, SIGTERM);
                if (getppid() != parent_pid) {
                    // We seem to have outlived out parent already.
                    exit(1);
                }

                close(listeningSocketFd); // Child doesn't need this.

                struct sockaddr_in connectedServerAddress = {};
                socklen_t connectedServerAddressLength = sizeof(connectedServerAddress); // ???
                if (getsockopt(acceptedSocketFd,
                               SOL_IP,
                               SO_ORIGINAL_DST,
                               (struct sockaddr*)&connectedServerAddress,
                               &connectedServerAddressLength
                               ) < 0) {
                    std::cerr << "Got non-redirected request" << std::endl;
#ifdef ALLOW_DIRECT_CONNECTIONS
                    // Useful for debugging.
                    if (getsockname(acceptedSocketFd,
                                    (struct sockaddr*)&connectedServerAddress,
                                    &connectedServerAddressLength
                                    ) < 0) {
                        close(acceptedSocketFd);
                        exit(1);
                    }
#else
                    close(acceptedSocketFd);
                    exit(1);
#endif
                }

                struct sockaddr_in connectedClientAddress = {};
                socklen_t connectedClientAddressLength = sizeof(connectedClientAddress); // ???
                if (getpeername(acceptedSocketFd,
                                (struct sockaddr*)&connectedClientAddress,
                                &connectedClientAddressLength
                                ) < 0) {
                    close(acceptedSocketFd);
                    exit(1);
                }

                char clientHost[256] = {};
                inet_ntop(AF_INET, &connectedClientAddress.sin_addr, clientHost, sizeof(clientHost));

                char connectHost[256] = {};
                inet_ntop(AF_INET, &connectedServerAddress.sin_addr, connectHost, sizeof(connectHost));
                int connectPort = ntohs(connectedServerAddress.sin_port);
                std::cerr << "Connect " << clientHost << " -> " << connectHost << ":" << connectPort << " (" << acceptedSocketFd << ")" << std::endl;

                Proxy proxy(proxySettings, acceptedSocketFd, clientHost, connectHost, connectPort);
                try {
                    proxy.run();
                } catch (const std::exception& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
                // Reset the connection (well, try)
                connectedServerAddress.sin_family = AF_UNSPEC;
                connect(acceptedSocketFd, (struct sockaddr*)&connectedServerAddress, sizeof(connectedServerAddress));
                close(acceptedSocketFd);
                std::cerr << "Close   " << clientHost << " -> " << connectHost << ":" << connectPort << " (" << acceptedSocketFd << ")" << std::endl;
                exit(0);
            } else {
                close(acceptedSocketFd); // Parent doesn't need this (anymore).
            }
        }
    }
};

int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage();
        exit(1);
    }
    int proxyPort;
    int listenPort;
    try {
        proxyPort = std::stoi(argv[2]);
        listenPort = std::stoi(argv[3]);
    } catch (const std::invalid_argument&) {
        print_usage();
        exit(1);
    }
    Server(ProxySettings(argv[1], proxyPort), listenPort).run();

    // Unreachable?
    return 1;
}
