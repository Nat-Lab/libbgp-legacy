#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <utility>
#include <stdlib.h>
#include "libbgp.h"

namespace LibBGP {

namespace Parsers {
template <typename T> T getValue(uint8_t **buffer) {
    uint8_t *buf = *buffer;
    size_t sz = sizeof(T);
    T var;
    memcpy(&var, buf, sz);
    *buffer = buf + sz;
    return var;

}

int parseHeader (uint8_t *buffer, BGPPacket *parsed) {
    if (memcmp(buffer, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 16) != 0)
        return -1;

    buffer += 16;

    parsed->length = ntohs(getValue<uint16_t> (&buffer));

    if (parsed->length > 4096) return -1;

    parsed->type = getValue<uint8_t> (&buffer);

    switch (parsed->type) {
        case 1: return parseOpenMessage(buffer, parsed); break;
        case 2: return parseUpdateMessage(buffer, parsed); break;
        case 3: return parseNofiticationMessage(buffer, parsed); break;
        case 4: return 0;
        default: return -1;
    }

}

int parseOpenMessage(uint8_t *buffer, BGPPacket *parsed) {
    auto *msg = new BGPOpenMessage;
    msg->version = getValue<uint8_t> (&buffer);
    msg->my_asn = ntohs(getValue<uint16_t> (&buffer));
    msg->hold_time = ntohs(getValue<uint16_t> (&buffer));
    msg->bgp_id = getValue<uint32_t> (&buffer);
    msg->opt_parm_len = getValue<uint8_t> (&buffer);

    int parsed_parm_len = 0;
    auto *parms = new std::vector<BGPOptionalParameter*>;

    while (parsed_parm_len < msg->opt_parm_len) {
        auto *parm = new BGPOptionalParameter;
        parm->type = getValue<uint8_t> (&buffer);
        parm->length = getValue<uint8_t> (&buffer);
        parm->value = (uint8_t *) malloc(parm->length);
        memcpy(parm->value, buffer, parm->length);

        if (parm->type == 2) { // Capability
            auto *caps = new std::vector<BGPCapability*>;
            int parsed_caps_len = 0;
            while (parsed_caps_len < parm->length) {
                auto *cap = new BGPCapability;
                cap->code = getValue<uint8_t> (&buffer);
                cap->length = getValue<uint8_t> (&buffer);
                cap->value = (uint8_t *) malloc(cap->length);
                memcpy(cap->value, buffer, cap->length);
                
                switch (cap->code) { // TODO: Other BGPCapabilities
                    case 65: { // 4b ASN
                        cap->as4_support = true;
                        cap->my_asn = ntohl(getValue<uint32_t> (&buffer));
                        break;
                    }
                    default: buffer += cap->length;
                }

                caps->push_back(cap);
                parsed_caps_len += cap->length + 2; // +2: uint8_t code + uint8_t length
            }

            parm->capabilities = caps;
        } else buffer += parm->length;

        parsed_parm_len += parm->length + 2; // +2: uint8_t type + uint8_t length
        parms->push_back(parm);
    }

    msg->opt_parms = parms;
    parsed->open = msg;
    return 0;
}

int parseUpdateMessage(uint8_t *buffer, BGPPacket *parsed) {
    auto *msg = new BGPUpdateMessage;
    msg->withdrawn_len = ntohs(getValue<uint16_t> (&buffer));
    auto *withdrawn_routes = new std::vector<BGPRoute*>;

    int parsed_routes_len = 0;
    while (parsed_routes_len < msg->withdrawn_len) {
        auto *route = new BGPRoute;
        route->length = getValue<uint8_t> (&buffer);

        int prefix_buffer_size = (route->length + 7) / 8;
        if (route->length > 32) return -1;
        memcpy(&route->prefix, buffer, prefix_buffer_size);

        buffer += prefix_buffer_size;
        parsed_routes_len += prefix_buffer_size + 1;
        withdrawn_routes->push_back(route);
    }
    
    msg->withdrawn_routes = withdrawn_routes;
    msg->path_attribute_length = ntohs(getValue<uint16_t> (&buffer));
    auto *attrs = new std::vector<BGPPathAttribute*>;

    int pasred_attrib_len = 0;
    while (pasred_attrib_len < msg->path_attribute_length) {
        auto *attr = new BGPPathAttribute;

        uint8_t flags = getValue<uint8_t> (&buffer);
        attr->optional = flags >> 7 & 0x1;
        attr->transitive = (flags >> 6) & 0x1;
        attr->partial = (flags >> 5) & 0x1;
        attr->extened = (flags >> 4) & 0x1;

        attr->type = getValue<uint8_t> (&buffer);

        if (attr->extened) attr->length = ntohs(getValue<uint16_t> (&buffer));
        else attr->length = getValue<uint8_t> (&buffer);

        pasred_attrib_len += 2 + (attr->extened ? 2 : 1); // 2: uint8_t flags + uint8_t type

        if (attr->length == 0 && attr->type != 6) { // 6: only attr always 0 len. 
            attrs->push_back(attr);
            continue;
        }

        switch (attr->type) {
            case 1:  // ORIGIN
                attr->origin = getValue<uint8_t> (&buffer); 
                pasred_attrib_len++; 
                break;
            case 2: { // AS_PATH
                auto *as_path = new BGPASPath;
                as_path->type = getValue<uint8_t> (&buffer);
                as_path->length = getValue<uint8_t> (&buffer);
                auto *path = new std::vector<uint32_t>;
                for (int i = 0; i < as_path->length; i++)
                    path->push_back(ntohs(getValue<uint16_t> (&buffer)));
                as_path->path = path;
                attr->as_path = as_path;
                pasred_attrib_len += 2 + 2 * as_path->length;
                break;
            }
            case 3: // NEXTHOP
                attr->next_hop = getValue<uint32_t> (&buffer); 
                pasred_attrib_len +=4; 
                break;
            case 4: // MED
                attr->med = ntohl(getValue<uint32_t> (&buffer)); 
                pasred_attrib_len +=4;
                break;
            case 5: // L_PREF
                attr->local_pref = ntohl(getValue<uint32_t> (&buffer)); 
                pasred_attrib_len +=4; 
                break;
            case 6: // AA
                if (attr->length != 0) return -1;
                else attr->atomic_aggregate = true;
                break;
            case 7: // AGGR
                attr->aggregator_asn = ntohs(getValue<uint16_t> (&buffer));
                attr->aggregator = getValue<uint32_t> (&buffer);
                pasred_attrib_len +=6;
                break;
            case 17: { // AS4_PATH
                auto *as_path = new BGPASPath;
                as_path->type = getValue<uint8_t> (&buffer);
                as_path->length = getValue<uint8_t> (&buffer);
                auto *path = new std::vector<uint32_t>;
                for (int i = 0; i < as_path->length; i++)
                    path->push_back(ntohl(getValue<uint32_t> (&buffer)));
                as_path->path = path;
                attr->as4_path = as_path;
                pasred_attrib_len += 2 + 4 * as_path->length;
                break;
            }
            case 18: // AGGR4
                attr->aggregator_asn4 = ntohl(getValue<uint32_t> (&buffer));
                attr->aggregator = getValue<uint32_t> (&buffer);
                pasred_attrib_len += 8;
                break;
            default: return -1;
        }
        attrs->push_back(attr);
    } // attr parse loop

    msg->path_attribute = attrs;

    int nlri_len = parsed->length - 23 - msg->withdrawn_len - msg->path_attribute_length;
    if (nlri_len < 0) return -1;

    auto *nlri = new std::vector<BGPRoute*>;
    parsed_routes_len = 0;
    while (parsed_routes_len < nlri_len) {
        auto *route = new BGPRoute;
        route->length = getValue<uint8_t> (&buffer);

        int prefix_buffer_size = (route->length + 7) / 8;
        if (route->length > 32) return -1;
        memcpy(&route->prefix, buffer, prefix_buffer_size);

        buffer += prefix_buffer_size;
        parsed_routes_len += prefix_buffer_size + 1;
        nlri->push_back(route);
    }
    msg->nlri = nlri;

    parsed->update = msg;
    return 0;
}
int parseNofiticationMessage(uint8_t *buffer, BGPPacket *parsed) {
    // TODO
}

} // Parsers

int Parse(uint8_t *buffer, BGPPacket *parsed) {
    return Parsers::parseHeader(buffer, parsed);
}

} // LibBGP