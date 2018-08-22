# Transproxify

Transparently redirect network traffic through an HTTP or SOCKSv4/5 proxy.

## Use cases

- Proxy connections without having to manually configure clients.
- Proxy applications which don't have native proxying support.
- Add transparent proxying capabilities to a non-transparent intercepting proxy, such as ZAP.

## Features

- Transparently proxy TCP and/or UDP traffic.
- HTTP, SOCKSv4, and SOCKSv5 upstream proxy support.
- Upstream proxy username and password support.

## QA

### Where do I run Transproxify?

Transproxify can be run on a client, router, or man-in-the-middle machine.

### How do I get traffic routed to Transproxify?

Use iptables. The required iptables rules required are different depending on the setup chosen.

For example, routers (and man-in-the-middle machines) can redirect HTTP and HTTPS traffic through Transproxify to proxyserver:8080 using:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp \
    --match multiport --dports 80,443 \
    -j REDIRECT --to-port 10000
transproxify proxyserver 8080 10000
```

Clients may also be able to redirect their own traffic using:

```sh
iptables -t nat -A OUTPUT -p tcp \
    --match multiport --dports 80,443 \
    -j REDIRECT --to-port 10000
transproxify proxyserver 8080 10000
```

### Can I redirect UDP traffic?

Yes! In order to do this, you must use the `-r udp` option, and a suitable proxy (such as socks5, using `-t socks5`).

You can run multiple (non-colliding) instances of Transproxify at the same time in order to proxy both TCP and UDP

### Can I proxy ICMP or other non-TCP/UDP traffic?

No. Only basic TCP and UDP are supported, as Transproxify relies on the capabilities of upstream proxies.

### Do you support IPv6?

Unsupported. Maybe later...

### Why is this written in C++?

Yes, that is true.

### Startup error: could not bind to address and port

It's a bug. Seems to start working again if you leave it a while.

### SECURITY DISCLAIMER

Like many forms of networking software, proxies can pose a significant risk to
network security. Transproxify provides no guarantees about communication
confidentiality, integrity, authenticity, or availability.

In particular, all tunnels and proxy credentials are transferred in cleartext
across the network. Any user on the network can use transproxify without
authentication, thus gaining access to the upstream proxy. Client applications
should enforce their own security where possible (such as TLS).

The author(s) of this software cannot be held responsible for any loss,
damage, or otherwise bad thing which happens as a result of using this
software. This includes, but is not limited to, data compromise, loss of
service or integrity, and remote code execution.

This tool is provided in good faith. Use at your own risk.



Copyright Ashley Newson 2018.
