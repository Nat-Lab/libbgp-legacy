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

int parseBanner (ParserPair *pair) {
    uint8_t *buffer = pair->first;
    BGPPacket *parsed = pair->second;

    if (memcmp(buffer, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 16) != 0)
        return -1;

    pair->first += 16;
    return parseHeader(pair);
}

int parseHeader (ParserPair *pair) {
    uint8_t *buffer = pair->first;
    BGPPacket *parsed = pair->second;
    
    parsed->length = ntohs(getValue<uint16_t> (&buffer));

    if (parsed->length > 4096) return -1;

    parsed->type = getValue<uint8_t> (&buffer);

    pair->first = buffer;

    switch(parsed->type) {
        case 1: return parseOpenMessage(pair); break;
        case 2: return parseUpdateMessage(pair); break;
        case 3: return parseNofiticationMessage(pair); break;
        case 4: return parseKeepaliveMessage(pair); break;
        default: return -1;
    }

}

int parseOpenMessage(ParserPair *pair) {
    uint8_t *buffer = pair->first;
    BGPPacket *parsed = pair->second;

    BGPOpenMessage *msg = new BGPOpenMessage;
    msg->version = getValue<uint8_t> (&buffer);
    msg->my_asn = ntohs(getValue<uint16_t> (&buffer));
    msg->hold_time = ntohs(getValue<uint16_t> (&buffer));
    msg->bgp_id = getValue<uint32_t> (&buffer);
    msg->opt_parm_len = getValue<uint8_t> (&buffer);

    if (msg->opt_parm_len < 2) return -1;

    int parsed_parm_len = 0;
    std::vector<BGPOptionalParameter*> *parms = new std::vector<BGPOptionalParameter*>;

    while (parsed_parm_len < msg->opt_parm_len) {
        BGPOptionalParameter *parm = new BGPOptionalParameter;
        parm->type = getValue<uint8_t> (&buffer);
        parm->length = getValue<uint8_t> (&buffer);
        parm->value = (uint8_t *) malloc(parm->length);
        memcpy(parm->value, buffer, parm->length);

        buffer += parm->length;
        parsed_parm_len += parm->length + 2;
        parms->push_back(parm);
    }

    msg->opt_parms = parms;
    parsed->open = msg;
    return 0;
}
int parseUpdateMessage(ParserPair *pair) {
    uint8_t *buffer = pair->first;
    BGPPacket *parsed = pair->second;

    BGPUpdateMessage *msg = new BGPUpdateMessage;
    msg->withdrawn_len = ntohs(getValue<uint16_t> (&buffer));
    std::vector<BGPRoute*> *withdrawn_routes = new std::vector<BGPRoute*>;

    int parsed_routes_len = 0;
    while (parsed_routes_len < msg->withdrawn_len) {
        BGPRoute *route = new BGPRoute;
        route->length = getValue<uint8_t> (&buffer);
        if (route->length > 32) return -1;
        route->prefix = (uint8_t *) malloc(route->length);
        memcpy(route->prefix, buffer, route->length);

        buffer += route->length;
        parsed_routes_len += route->length + 1;
        withdrawn_routes->push_back(route);
    }
    
    msg->withdrawn_routes = withdrawn_routes;
    msg->path_attribute_length = ntohs(getValue<uint16_t> (&buffer));
    std::vector<BGPPathAttribute*> *attrs = new std::vector<BGPPathAttribute*>;

    int pasred_attrib_len = 0;
    while (pasred_attrib_len < msg->path_attribute_length) {
        BGPPathAttribute *attr = new BGPPathAttribute;

        uint8_t flags = getValue<uint8_t> (&buffer);
        attr->optional = flags & 0x1;
        attr->transitive = (flags >> 1) & 0x1;
        attr->partial = (flags >> 2) & 0x1;
        attr->extened = (flags >> 3) & 0x1;

        attr->type = getValue<uint8_t> (&buffer);

        if (attr->extened) attr->length = ntohs(getValue<uint16_t> (&buffer));
        else attr->length = getValue<uint8_t> (&buffer);

        pasred_attrib_len += 2 + (attr->extened ? 2 : 1);


        if (attr->length == 0 && attr->type != 6) { // 6: only attr allow 0 len. 
            attrs->push_back(attr);
            continue;
        }

        switch (attr->type) {
            case 1: 
                attr->origin = getValue<uint8_t> (&buffer); 
                pasred_attrib_len++; 
                break;
            case 2: { // TODO: 4b ASN
                BGPASPath *as_path = new BGPASPath;
                as_path->type = getValue<uint8_t> (&buffer);
                as_path->length = getValue<uint8_t> (&buffer);
                std::vector<uint16_t> *path = new std::vector<uint16_t>;
                for (int i = 0; i < as_path->length; i++)
                    path->push_back(ntohs(getValue<uint16_t> (&buffer)));
                as_path->path = path;
                attr->as_path = as_path;
                pasred_attrib_len += 2 + 2 * as_path->length;
                break;
            }
            case 3: 
                attr->next_hop = getValue<uint32_t> (&buffer); 
                pasred_attrib_len +=4; 
                break;
            case 4: 
                attr->med = ntohl(getValue<uint32_t> (&buffer)); 
                pasred_attrib_len +=4;
                break;
            case 5: 
                attr->local_pref = ntohl(getValue<uint32_t> (&buffer)); 
                pasred_attrib_len +=4; 
                break;
            case 6: 
                if (attr->length != 0) return -1;
                else attr->atomic_aggregate = true;
                break;
            case 7:
                attr->aggregator_asn = ntohs(getValue<uint16_t> (&buffer));
                attr->aggregator = getValue<uint32_t> (&buffer);
                pasred_attrib_len +=6;
                break;
            default: return -1;
        }
        attrs->push_back(attr);
    } // attr parse loop

    msg->path_attribute = attrs;

    int nlri_len = parsed->length - 23 - msg->withdrawn_len - msg->path_attribute_length;
    if (nlri_len < 0) return -1;

    std::vector<BGPRoute*> *nlri = new std::vector<BGPRoute*>;
    parsed_routes_len = 0;
    while (parsed_routes_len < nlri_len) {
        BGPRoute *route = new BGPRoute;
        route->length = getValue<uint8_t> (&buffer);
        if (route->length > 32) return -1;
        route->prefix = (uint8_t *) malloc(route->length);
        memcpy(route->prefix, buffer, route->length);

        buffer += route->length;
        parsed_routes_len += route->length + 1;
        nlri->push_back(route);
    }
    msg->nlri = nlri;

    parsed->update = msg;
    return 0;
}
int parseNofiticationMessage(ParserPair *pair) {
    // TODO
}

int parseKeepaliveMessage(ParserPair *pair) {
    // TODO
}

} // Parsers

int Parse(uint8_t *buffer, BGPPacket *parsed) {
    ParserPair pair = std::make_pair(buffer, parsed);

    return Parsers::parseBanner(&pair);
}

} // LibBGP