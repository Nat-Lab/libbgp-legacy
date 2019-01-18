#ifndef LIBBGP_H
#define LIBBGP_H

#include <utility>
#include <stdint.h>
#include <vector>

namespace LibBGP {

typedef struct BGPOptionalParameter {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
} BGPOptionalParameter;

typedef struct BGPOpenMessage {
    uint8_t version;
    uint16_t my_asn;
    uint16_t hold_time;
    uint32_t bgp_id;
    uint8_t opt_parm_len;
    std::vector<BGPOptionalParameter*> *opt_parms;
} BGPOpenMessage;

typedef struct BGPASPath {
    uint8_t type;
    uint8_t length;
    std::vector<uint16_t> *path;
} BGPASPath;

typedef struct BGPRoute {
    uint8_t length;
    uint8_t* prefix;
} BGPRoute;

typedef struct BGPPathAttribute {
    bool optional;
    bool transitive;
    bool partial;
    bool extened;
    uint8_t type;
    uint16_t length;

    uint8_t origin;
    BGPASPath *as_path;
    uint32_t next_hop;
    uint32_t med;
    uint32_t local_pref;
    bool atomic_aggregate;
    uint16_t aggregator_asn;
    uint32_t aggregator;
} BGPPathAttribute;

typedef struct BGPUpdateMessage {
    uint16_t withdrawn_len;
    std::vector<BGPRoute*> *withdrawn_routes;
    uint16_t path_attribute_length;
    std::vector<BGPPathAttribute*> *path_attribute;
    std::vector<BGPRoute*> *nlri;
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
