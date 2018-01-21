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

    pair->first = buffer += 16;
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
    msg->bgp_id = ntohl(getValue<uint32_t> (&buffer));
    msg->opt_parm_len = getValue<uint8_t> (&buffer);

    if (msg->opt_parm_len < 2) return -1;

    int parsed_parm_len = 0;
    std::vector<BGPOptionalParameters*> parms;

    while (parsed_parm_len < msg->opt_parm_len) {
        parsed_parm_len += 2;
        BGPOptionalParameters *parm = new BGPOptionalParameters;
        parm->type = getValue<uint8_t> (&buffer);
        parm->length = getValue<uint8_t> (&buffer);
        parm->value = (uint8_t *) malloc(parm->length);
        memcpy(parm->value, &buffer, parm->length);
        buffer += parm->length;

        parms.push_back(parm);
    }

    parsed->open = msg;
    return 0;
}
int parseUpdateMessage(ParserPair *pair) {
    // TODO
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