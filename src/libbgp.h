#ifndef LIBBGP_H
#define LIBBGP_H

#include <stdint.h>
#include <stdlib.h>
#include <utility>
#include <vector>

namespace LibBGP {

typedef struct BGPCapability {
    uint8_t code;
    uint8_t length;
    uint8_t* value;

    bool as4_support;
    uint32_t my_asn;
 
    BGPCapability();
} BGPCapability;

typedef struct BGPOptionalParameter {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
    std::vector<BGPCapability*> *capabilities;

    BGPOptionalParameter();
} BGPOptionalParameter;

typedef struct BGPOpenMessage {
    uint8_t version;
    uint16_t my_asn;
    uint16_t hold_time;
    uint32_t bgp_id;
    uint8_t opt_parm_len;
    std::vector<BGPOptionalParameter*> *opt_parms;

    /* a few methods for some common things, so that we don't have to read/make
     * every opt_parms ourself.
     */
    BGPOpenMessage();
    BGPOpenMessage(uint32_t my_asn, uint16_t hold_time, uint32_t bgp_id);
    void set4BAsn(uint32_t my_asn);
    void remove4BAsn();
    uint32_t getAsn();
} BGPOpenMessage;

typedef struct BGPASPath {
    uint8_t type;
    uint8_t length;
    std::vector<uint32_t> *path;

    BGPASPath();
} BGPASPath;

typedef struct BGPRoute {
    uint8_t length;
    uint32_t prefix;

    BGPRoute();
} BGPRoute;

typedef struct BGPPathAttribute {
    bool optional;
    bool transitive;
    bool partial;
    bool extened;
    bool peer_as4_ok;
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

    BGPPathAttribute();
} BGPPathAttribute;

typedef struct BGPUpdateMessage {
    uint16_t withdrawn_len;
    std::vector<BGPRoute*> *withdrawn_routes;
    uint16_t path_attribute_length;
    std::vector<BGPPathAttribute*> *path_attribute;
    std::vector<BGPRoute*> *nlri;

    BGPUpdateMessage();

    /* a few methods for some common things, so that we don't have to read/make
     * every attribute ourself.
     */
    BGPPathAttribute* getAttrib(uint8_t attrib_type);
    void addAttrib(BGPPathAttribute *attrib);

    uint32_t getNexthop();
    void setNexthop(uint32_t nexthop);

    std::vector<uint32_t>* getAsPath();
    void setAsPath(std::vector<uint32_t>* path, bool as4);

    uint8_t getOrigin();
    void setOrigin(uint8_t origin);

    uint32_t getMed();
    void setMed(uint32_t med);

    uint32_t getLocalPref();
    void setLocalPref(uint32_t local_pref);

    void addPrefix(uint32_t prefix, uint8_t length, bool is_withdraw);
} BGPUpdateMessage;

typedef struct BGPNotificationMessage {

} BGPNotificationMessage;

typedef struct BGPPacket {
    uint16_t length;
    uint8_t type;
    BGPOpenMessage *open;
    BGPUpdateMessage *update;
    BGPNotificationMessage *notification;

    BGPPacket();
    BGPPacket(uint8_t *buffer);
    int write(uint8_t *buffer);
    int read(uint8_t *buffer);
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
}

int Build(uint8_t *buffer, BGPPacket *source);
int Parse(uint8_t *buffer, BGPPacket *parsed);

}

#endif // LIBBGP_H
