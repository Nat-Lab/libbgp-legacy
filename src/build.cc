#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include "libbgp.h"

namespace LibBGP {

namespace Builders {

template <typename T> size_t putValue(uint8_t **buffer, T value) {
    uint8_t *buf = *buffer;
    size_t sz = sizeof(T);
    memcpy(buf, &value, sz);
    *buffer = buf + sz;
    return sz;
}

int buildHeader(uint8_t *buffer, BGPPacket *source) {
    int this_len = 0;

    memset(buffer, '\xff', 16);
    buffer += 16; this_len += 16;

    this_len += putValue<uint16_t> (&buffer, htons(0));
    this_len += putValue<uint8_t> (&buffer, source->type);

    switch (source->type) {
        case 1: return this_len + buildOpenMessage(buffer, source);
        case 2: return this_len + buildUpdateMessage(buffer, source);
        case 3: return this_len + buildNofiticationMessage(buffer, source);
        case 4: return this_len + buildKeepaliveMessage(buffer, source);
        default: return this_len;
    }
}

int buildOpenMessage(uint8_t *buffer, BGPPacket *source) {
    int this_len = 0;
    auto *msg = source->open;

    this_len += putValue<uint8_t> (&buffer, msg->version);
    this_len += putValue<uint16_t> (&buffer, htons(msg->my_asn));
    this_len += putValue<uint16_t> (&buffer, htons(msg->hold_time));
    this_len += putValue<uint32_t> (&buffer, msg->bgp_id);
    this_len += putValue<uint8_t> (&buffer, 0);

    int parm_len = 0;
    auto *parms = msg->opt_parms;
    std::for_each(parms->begin(), parms->end(), [&parm_len, &buffer](BGPOptionalParameter *param) {
        parm_len += putValue<uint8_t> (&buffer, param->type);
        parm_len += putValue<uint8_t> (&buffer, param->length);
        if (param->value) {
            memcpy(buffer, param->value, param->length);
            buffer += param->length;
            parm_len += param->length;
        } else if (param->type == 2 && param->capability) { // Capability
            auto *cap = param->capability;
            parm_len += putValue<uint8_t> (&buffer, cap->code);
            parm_len += putValue<uint8_t> (&buffer, cap->length);

            if (cap->value) {
                memcpy(buffer, cap->value, cap->length);
                buffer += cap->length;
                parm_len += cap->length;
            } else switch (cap->code) {
                case 65: {
                    parm_len += putValue<uint32_t> (&buffer, htonl(cap->my_asn));
                    break;
                };
                default: break;
            };
        }
    });

    memcpy(buffer - parm_len - 1, &parm_len, sizeof(uint8_t)); // put parm_len
    
    return this_len + parm_len;
}

int buildUpdateMessage(uint8_t *buffer, BGPPacket *source) {

}

int buildNofiticationMessage(uint8_t *buffer, BGPPacket *source) {

}

int buildKeepaliveMessage(uint8_t *buffer, BGPPacket *source) {

}

} // Builders

int Build(uint8_t *buffer, BGPPacket *source) {
    size_t len = Builders::buildHeader(buffer, source);

    uint8_t *ptr = buffer + 16;
    Builders::putValue<uint16_t> (&ptr, (uint16_t) htons(len)); // put len

    return len;
}

} // LibBGP