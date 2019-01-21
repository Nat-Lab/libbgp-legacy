#ifndef LIBBGP_H
#define LIBBGP_H

#include <stdint.h>
#include <stdlib.h>
#include <utility>
#include <vector>

namespace LibBGP {

typedef struct BGPCapabilities {
    uint8_t code;
    uint8_t length;
    uint8_t* value;

    bool as4_support;
    uint32_t my_asn;
 
} BGPCapabilities;

typedef struct BGPOptionalParameter {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
    BGPCapabilities *capability;
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
    std::vector<uint32_t> *path;
} BGPASPath;

typedef struct BGPRoute {
    uint8_t length;
    uint32_t prefix;
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
    BGPASPath *as4_path;
    uint32_t next_hop;
    uint32_t med;
    uint32_t local_pref;
    bool atomic_aggregate;
    uint16_t aggregator_asn;
    uint32_t aggregator;
    uint32_t aggregator_asn4;
} BGPPathAttribute;

typedef struct BGPUpdateMessage {
    uint16_t withdrawn_len;
    std::vector<BGPRoute*> *withdrawn_routes;
    uint16_t path_attribute_length;
    std::vector<BGPPathAttribute*> *path_attribute;
    std::vector<BGPRoute*> *nlri;
} BGPUpdateMessage;

typedef struct BGPNotificationMessage {

} BGPNotificationMessage;

typedef struct BGPPacket {
    uint16_t length;
    uint8_t type;
    uint8_t version;
    BGPOpenMessage *open;
    BGPUpdateMessage *update;
    BGPNotificationMessage *notification;
} BGPPacket;

namespace Parsers {
    template <typename T> T getValue(uint8_t **buffer);
    int parseHeader(uint8_t *buffer, BGPPacket *parsed);
    int parseOpenMessage(uint8_t *buffer, BGPPacket *parsed);
    int parseUpdateMessage(uint8_t *buffer, BGPPacket *parsed);
    int parseNofiticationMessage(uint8_t *buffer, BGPPacket *parsed);
}

namespace Builders {
    template <typename T> size_t putValue(uint8_t **buffer, T value);
    int buildHeader(uint8_t *buffer, BGPPacket *source);
    int buildOpenMessage(uint8_t *buffer, BGPPacket *source);
    int buildUpdateMessage(uint8_t *buffer, BGPPacket *source);
    int buildNofiticationMessage(uint8_t *buffer, BGPPacket *source);
    int buildKeepaliveMessage(uint8_t *buffer, BGPPacket *source);
}

int Build(uint8_t *buffer, BGPPacket *source);
int Parse(uint8_t *buffer, BGPPacket *parsed);

}

#endif // LIBBGP_H
