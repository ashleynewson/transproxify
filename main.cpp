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
#include <termios.h>

void print_usage() {
    const char* usage = R"END_USAGE(Transproxify - Copyright Ashley Newson 2018

Usage:
    transproxify [OPTIONS...] PROXY_HOST PROXY_PORT LISTEN_PORT

Synopsis:
    Perform transparent proxying through an HTTP or SOCKS proxy.

    Not all software supports configuring proxies. With transproxify, you can
    force communications to pass through a proxy from inside the router.

    Transproxify listens on a given port accepting redirected traffic. When a
    redirected client connects to transproxify, transproxify will connect to a
    given proxy server and establish a tunnel for forwarding data between the
    client and its intended server, all transparent to the client.

    Transproxify will not intercept traffic by itself. You may need to alter
    firewall settings. For example, to use transproxify to proxy HTTP and HTTPS
    traffic on ports 80 and 443 via proxyserver:8080 HTTP proxy, you might use:

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

Options:
    -t PROTOCOL
        Specify the upstream proxy's protocol. Default is http.
        Valid choices are: http, socks4
    -u USERNAME
        Specify the username for proxy authentication.
    -p
        Prompt for a password for proxy authentication at startup.
    -P PASSWORD
        Specify the password for proxy authentication. Note that users on the
        same system can see passwords entered like this in process tables.

HTTP proxy authentication:
    If a username and password are supplied, transproxy will send a
    Proxy-Authorization header using the basic authorization scheme.

SOCKS4 proxy authentication:
    If a username or password is supplied, transproxy will use this as the
    UserId in requests to the socks server. Else, a blank UserID is sent.
)END_USAGE";

    std::cerr << usage;
}


/// read(), but keep reading until count bytes extracted.
///
/// Will only return less than count bytes if EOF is reached.
///
/// Returns -1 on any errors (well, whatever read() does).
ssize_t read_exactly(int fd, void* buf, size_t count) {
    int i = 0;
    while (i < count) {
        int r = read(fd, ((char*)buf)+i, count-i);
        if (r < 0) {
            return r;
        } else if (r == 0) {
            return i;
        } else {
            i += r;
        }
    }
    return i;
}

/// Encode string to base64
std::string base64encode(const std::string& plain) {
    const unsigned char* values = (const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::stringstream stream;
    const unsigned char* bytes = (const unsigned char*)plain.c_str();
    size_t len = plain.length();
    size_t i;
    for (i = 0; i+2 < len; i+=3) {
        stream.put(values[((bytes[i+0] & 0b11111100) >> 2)]);
        stream.put(values[((bytes[i+0] & 0b00000011) << 4) + ((bytes[i+1] & 0b11110000) >> 4)]);
        stream.put(values[((bytes[i+1] & 0b00001111) << 2) + ((bytes[i+2] & 0b11000000) >> 6)]);
        stream.put(values[((bytes[i+2] & 0b00111111)     )]);
    }
    switch(len - i) {
    case 0:
        break;
    case 1:
        stream.put(values[((bytes[i+0] & 0b11111100) >> 2)]);
        stream.put(values[((bytes[i+0] & 0b00000011) << 4)]);
        stream.put('=');
        stream.put('=');
        break;
    case 2:
        stream.put(values[((bytes[i+0] & 0b11111100) >> 2)]);
        stream.put(values[((bytes[i+0] & 0b00000011) << 4) + ((bytes[i+1] & 0b11110000) >> 4)]);
        stream.put(values[((bytes[i+1] & 0b00001111) << 2)]);
        stream.put('=');
        break;
    }
    return stream.str();
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
public:
    enum class Protocol {
        HTTP,
        SOCKS4,
    };

private:
    friend class Proxy;
    Protocol protocol;
    std::string username;
    std::string password;
    struct sockaddr_in proxyAddress;

public:
    ProxySettings(Protocol protocol, const std::string& proxyHost, int proxyPort, const std::string& username, const std::string& password):
        protocol(protocol),
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

        switch (protocol) {
        case Protocol::HTTP:
            if (username.empty() != password.empty()) {
                throw std::runtime_error("got only one of username or password for HTTP");
            }
            if (!username.empty() && username.find(':') != std::string::npos) {
                throw std::runtime_error("HTTP username cannot contain ':' character");
            }
            break;
        case Protocol::SOCKS4:
            if (!username.empty() && !password.empty()) {
                throw std::runtime_error("need only one of username or password for SOCKS4");
            }
            break;
        default:
            throw std::runtime_error("bad protocol setting");
        }
    }
};

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

    void http_connect(int proxySocketFd) {
        std::string tunnelRequest =
            "CONNECT " + targetHost + ":" + std::to_string(targetPort) + " HTTP/1.1\n"
            + "Host: " + targetHost + ":" + std::to_string(targetPort) + "\n"
            + (!settings.username.empty() ? "Proxy-Authorization: Basic " + base64encode(settings.username + ":" + settings.password) + "\n" : "")
            + "\n";

        if (write(proxySocketFd, tunnelRequest.c_str(), tunnelRequest.length()) < 0) {
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

        Socks4Packet request = {4, 1, targetAddress.sin_port, targetAddress.sin_addr.s_addr};

        // Might generate two TCP packets. Dunno if that breaks anything.
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
        if (write(proxySocketFd, &request, sizeof(request)) < 0
            || write(proxySocketFd, userId, userIdLen) < 0
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

        switch (settings.protocol) {
        case ProxySettings::Protocol::HTTP:
            http_connect(proxySocketFd);
            break;
        case ProxySettings::Protocol::SOCKS4:
            socks4_connect(proxySocketFd);
            break;
        default:
            throw std::runtime_error("invalid proxy protocol");
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

                Proxy proxy(proxySettings, acceptedSocketFd, clientHost, connectedServerAddress);
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
    ProxySettings::Protocol protocol = ProxySettings::Protocol::HTTP;
    std::string proxyHost;
    int proxyPort;
    int listenPort;
    std::string username;
    std::string password;
    bool promptPassword;

    int c;
    while ((c = getopt(argc, argv, "t:u:pP:")) != -1) {
        switch (c) {
        case 't':
            if (strcmp(optarg, "http") == 0) {
                protocol = ProxySettings::Protocol::HTTP;
            }
            else if (strcmp(optarg, "socks4") == 0) {
                protocol = ProxySettings::Protocol::SOCKS4;
            }
            else {
                std::cerr << "Unknown protocol" << std::endl;
                print_usage();
                exit(1);
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'p':
            promptPassword = true;
            break;
        case 'P':
            password = optarg;
            break;
        default:
            std::cerr << "Bad option" << std::endl;
            print_usage();
            exit(1);
        }
    }
    if (argc - optind != 3) {
        print_usage();
        exit(1);
    }
    try {
        proxyHost = argv[optind];
        proxyPort = std::stoi(argv[optind+1]);
        listenPort = std::stoi(argv[optind+2]);
    } catch (const std::invalid_argument&) {
        print_usage();
        exit(1);
    }

    if (promptPassword) {
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);
        tty.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        std::cerr << "Please enter your proxy's password:" << std::endl;
        char passwordCstr[256] = {};
        std::cin.getline(passwordCstr, 256);
        password = passwordCstr;
        tty.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        if (std::cin.fail()) {
            std::cerr << "Failed to get password from stdin" << std::endl;
            exit(1);
        }
    }

    Server(ProxySettings(protocol, proxyHost, proxyPort, username, password), listenPort).run();

    // Unreachable?
    return 1;
}
