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
        case 4: return this_len;
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
    auto parms = msg->opt_parms;
    if (parms) std::for_each(parms->begin(), parms->end(), [&parm_len, &buffer](BGPOptionalParameter *param) {
        parm_len += putValue<uint8_t> (&buffer, param->type);
        parm_len += putValue<uint8_t> (&buffer, param->length);
        if (param->value) {
            memcpy(buffer, param->value, param->length);
            buffer += param->length;
            parm_len += param->length;
        } else if (param->type == 2 && param->capabilities) { // Capability
            auto *caps = param->capabilities;
            int caps_len = 0;
            std::for_each(caps->begin(), caps->end(), [&caps_len, &buffer](BGPCapability *cap) {
                caps_len += putValue<uint8_t> (&buffer, cap->code);

                if (cap->value) {
                    caps_len += putValue<uint8_t> (&buffer, cap->length);
                    memcpy(buffer, cap->value, cap->length);
                    buffer += cap->length;
                    caps_len += cap->length;
                } else switch (cap->code) {
                    case 65: {
                        caps_len += putValue<uint8_t> (&buffer, 4);
                        caps_len += putValue<uint32_t> (&buffer, htonl(cap->my_asn));
                        break;
                    };
                    default: break;
                }
            });

            memcpy(buffer - caps_len - 1, &caps_len, sizeof(uint8_t));
            parm_len += caps_len;            
        }
    });

    memcpy(buffer - parm_len - 1, &parm_len, sizeof(uint8_t)); // put parm_len
    
    return this_len + parm_len;
}

int buildUpdateMessage(uint8_t *buffer, BGPPacket *source) {
    int this_len = 0;
    auto *msg = source->update;

    this_len += putValue<uint16_t> (&buffer, htons(0)); // msg->withdrawn_len
    int withdrawn_len = 0;
    auto *withdrawn_routes = msg->withdrawn_routes;
    if (withdrawn_routes) std::for_each(withdrawn_routes->begin(), withdrawn_routes->end(), 
    [&withdrawn_len, &buffer](BGPRoute *route) {
        withdrawn_len += putValue<uint8_t> (&buffer, route->length);
        int prefix_buffer_size = (route->length + 7) / 8;
        memcpy(buffer, &route->prefix, prefix_buffer_size);
        withdrawn_len += prefix_buffer_size;
        buffer += prefix_buffer_size;
    });

    this_len += withdrawn_len;
    uint16_t withdrawn_len_n = htons(withdrawn_len);
    memcpy(buffer - withdrawn_len - 2, &withdrawn_len_n, sizeof(uint16_t));

    this_len += putValue<uint16_t> (&buffer, htons(0)); // msg->path_attribute_length
    int attrs_len = 0;
    auto attrs = msg->path_attribute;
    if (attrs) std::for_each(attrs->begin(), attrs->end(), [&attrs_len, &buffer](BGPPathAttribute *attr) {
        uint8_t flags = 0;
        flags |= (attr->optional << 7) | (attr->transitive << 6)| (attr->partial << 5) | (attr->extened << 4);
        attrs_len += putValue<uint8_t> (&buffer, flags);
        attrs_len += putValue<uint8_t> (&buffer, attr->type);

        if (attr->extened) attrs_len += putValue<uint16_t> (&buffer, htons(0));
        else attrs_len += putValue<uint8_t> (&buffer, 0);

        int attr_len = 0;
        switch (attr->type) {
            case 1:  // ORIGIN
                attr_len += putValue<uint8_t> (&buffer, attr->origin); 
                break;
            case 2: { // AS_PATH
                auto *as_path = attr->as_path;
                auto *path = as_path->path;
                attr_len += putValue<uint8_t> (&buffer, as_path->type);
                attr_len += putValue<uint8_t> (&buffer, path->size());
                
                for (int i = 0; i < path->size(); i++)
                    if (attr->peer_as4_ok) attr_len += putValue<uint16_t> (&buffer, htons(path->at(i)));
                    else attr_len += putValue<uint32_t> (&buffer, htonl(path->at(i)));
                break;
            }
            case 3: // NEXTHOP
                attr_len += putValue<uint32_t> (&buffer, attr->next_hop); 
                break;
            case 4: // MED
                attr_len += putValue<uint32_t> (&buffer, attr->med); 
                break;
            case 5: // L_PREF
                attr_len += putValue<uint32_t> (&buffer, attr->local_pref); 
                break;
            case 6: // AA
                break;
            case 7: // AGGR
                attr_len += putValue<uint16_t> (&buffer, htons(attr->aggregator_asn));
                attr_len += putValue<uint32_t> (&buffer, attr->aggregator);
                break;
            case 17: { // AS4_PATH
                auto *as_path = attr->as4_path;
                auto *path = as_path->path;
                attr_len += putValue<uint8_t> (&buffer, as_path->type);
                attr_len += putValue<uint8_t> (&buffer, path->size());
                
                for (int i = 0; i < path->size(); i++)
                    attr_len += putValue<uint32_t> (&buffer, htonl(path->at(i)));
                break;
            }
            case 18: // AGGR4
                attr_len += putValue<uint32_t> (&buffer, htonl(attr->aggregator_asn));
                attr_len += putValue<uint32_t> (&buffer, attr->aggregator);
                break;
            default: return -1;
        } // attr->type switch

        memcpy(buffer - attr_len - 1, &attr_len, sizeof(uint8_t));
        attrs_len += attr_len;
    }); // attr foreach

    this_len += attrs_len;
    uint16_t attrs_len_n = htons(attrs_len);
    memcpy(buffer - attrs_len - 2, &attrs_len_n, sizeof(uint16_t));

    auto nlri = msg->nlri;
    if (nlri) std::for_each(nlri->begin(), nlri->end(), [&this_len, &buffer](BGPRoute *route) {
        this_len += putValue<uint8_t> (&buffer, route->length);
        int prefix_buffer_size = (route->length + 7) / 8;
        memcpy(buffer, &route->prefix, prefix_buffer_size);
        this_len += prefix_buffer_size;
        buffer += prefix_buffer_size;
    });

    return this_len;
}

int buildNofiticationMessage(uint8_t *buffer, BGPPacket *source) {

}

} // Builders

int Build(uint8_t *buffer, BGPPacket *source) {
    size_t len = Builders::buildHeader(buffer, source);

    uint8_t *ptr = buffer + 16;
    Builders::putValue<uint16_t> (&ptr, (uint16_t) htons(len)); // put len

    return len;
}

} // LibBGP