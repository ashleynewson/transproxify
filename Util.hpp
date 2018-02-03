#ifndef HGUARD_UTIL
#define HGUARD_UTIL

#include <unistd.h>

/// read(), but keep reading until count bytes extracted.
///
/// Will only return less than count bytes if EOF is reached.
///
/// Returns -1 on any errors (well, whatever read() does).
static ssize_t read_exactly(int fd, void* buf, size_t count) {
    size_t i = 0;
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

/// Used for constructing packets before write.
static ssize_t build_packet(void* packet, size_t max_packet_length, size_t* packet_len, const void* buf, size_t count) {
    if (*packet_len + count > max_packet_length) {
        return -1;
    }
    memcpy((char*)packet + *packet_len, buf, count);
    *packet_len += count;
    return count;
}

/// write(), but keep writing until count bytes written.
///
/// Returns -1 on any errors (well, whatever read() does).
/// Otherwise, never returns less than count.
static ssize_t write_exactly(int fd, const void* buf, size_t count) {
    size_t i = 0;
    while (i < count) {
        int r = write(fd, ((const char*)buf)+i, count-i);
        if (r < 0) {
            return r;
        } else {
            i += r;
        }
    }
    return i;
}

/// Encode string to base64
static std::string base64encode(const std::string& plain) {
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

#endif
