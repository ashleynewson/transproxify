# Transproxify

Transparently redirect network traffic through an HTTP or SOCKSv4/5 proxy.

## Use cases

- Proxy connections without having to manually configure clients.
- Proxy applications which don't have native proxying support.
- Add transparent proxying capabilities to a non-transparent intercepting proxy, such as ZAP.

## Features

- Transparently proxy TCP traffic.
- HTTP, SOCKSv4, and SOCKSv5 upstream proxy support.
- Upstream proxy username and password support.

## QA

### Where do I run transproxify?

Transproxify can be run on a client, router, or man-in-the-middle machine.

### How do I get traffic routed to transproxify?

Use iptables. The required iptables rules required are different depending on the setup chosen.

Routers (and man-in-the-middle) machines can redirect traffic to transproxify using:

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

Not supported. Sorry :(

### Why is this written in C++?

Yes, that is true.



Copyright Ashley Newson 2018.
