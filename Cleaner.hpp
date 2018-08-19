#ifndef HGUARD_CLEANER
#define HGUARD_CLEANER

#include <memory>

class Cleaner {
private:
    class Trigger {
        bool enabled;
        std::function<void()> callback;
    public:
        Trigger(std::function<void()> callback):
            enabled(true),
            callback(callback)
        {
        }
        ~Trigger() {
            clean();
        }
        void disable() {
            enabled = false;
        }
        void clean() {
            if (enabled) {
                callback();
                enabled = false;
            }
        }
    };
    std::shared_ptr<Trigger> trigger;
public:
    Cleaner():
        trigger(nullptr)
    {
    }
    Cleaner(std::function<void()> callback):
        trigger(std::make_shared<Trigger>(callback))
    {
    }
    void disable() {
        if (trigger) {
            trigger->disable();
        }
    }
    void clean() {
        if (trigger) {
            trigger->clean();
        }
    }
};

#endif
