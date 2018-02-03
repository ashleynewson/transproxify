#ifndef HGUARD_CLEANER
#define HGUARD_CLEANER

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

#endif
