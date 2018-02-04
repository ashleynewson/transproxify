#ifndef HGUARD_PROXY
#define HGUARD_PROXY

#include "Util.hpp"
#include "Cleaner.hpp"
#include "ProxySettings.hpp"

class Proxy {
protected:
    ProxySettings settings;

public:
    // clientSocketFd becomes owned by Proxy
    Proxy(ProxySettings settings):
        settings(settings)
    {
    }

    virtual ~Proxy() {
    }
};

#endif
