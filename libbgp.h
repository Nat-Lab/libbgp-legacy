#ifndef LIBBGP_H
#define LIBBGP_H

#include <utility>
#include <stdint.h>
#include <vector>

namespace LibBGP {

typedef struct BGPOptionalParameters {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
} BGPOptionalParameters;

typedef struct BGPOpenMessage {
    uint8_t version;
    uint16_t my_asn;
    uint16_t hold_time;
    uint32_t bgp_id;
    uint8_t opt_parm_len;
    std::vector<BGPOptionalParameters*> *opt_parm;
} BGPOpenMessage;

typedef struct BGPUpdateMessage {
    uint16_t withdrawn_len;
    //std::vector<
} BGPUpdateMessage;

typedef struct BGPKeepaliveMessage {

} BGPKeepaliveMessage;

typedef struct BGPNotificationMessage {

} BGPNotificationMessage;

typedef struct BGPPacket {
    uint16_t length;
    uint8_t type;
    uint8_t version;
    BGPOpenMessage *open;
    BGPUpdateMessage *update;
    BGPKeepaliveMessage *keepalive;
    BGPNotificationMessage *notification;
} BGPPacket;

typedef std::pair<uint8_t*, BGPPacket*> ParserPair;

namespace Parsers {
    template <typename T> T getValue(uint8_t **buffer);
    int parseBanner(ParserPair *pair);
    int parseHeader(ParserPair *pair);
    int parseOpenMessage(ParserPair *pair);
    int parseUpdateMessage(ParserPair *pair);
    int parseNofiticationMessage(ParserPair *pair);
    int parseKeepaliveMessage(ParserPair *pair);
}

int Parse(uint8_t *buffer, BGPPacket *parsed);

}

#endif // LIBBGP_H
