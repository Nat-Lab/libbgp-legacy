#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include "libbgp.h"
#include <stdio.h>

namespace LibBGP {

BGPPacket::BGPPacket() {
    memset(this, 0, sizeof(BGPPacket));
}

BGPPacket::BGPPacket(uint8_t *buffer) {
    memset(this, 0, sizeof(BGPPacket));
    this->read(buffer);
}

int BGPPacket::write(uint8_t *buffer) {
    return Build(buffer, this);
}

uint8_t* BGPPacket::read(uint8_t *buffer) {
    return Parse(buffer, this);
}

BGPOptionalParameter::BGPOptionalParameter() {
    memset(this, 0, sizeof(BGPOptionalParameter));
}

BGPCapability::BGPCapability() {
    memset(this, 0, sizeof(BGPCapability));
}

BGPASPath::BGPASPath() {
    memset(this, 0, sizeof(BGPASPath));
}

BGPRoute::BGPRoute() {
    memset(this, 0, sizeof(BGPRoute));
}

BGPPathAttribute::BGPPathAttribute() {
    memset(this, 0, sizeof(BGPPathAttribute));
}

BGPUpdateMessage::BGPUpdateMessage() {
    memset(this, 0, sizeof(BGPUpdateMessage));
}

BGPOpenMessage::BGPOpenMessage() {
    memset(this, 0, sizeof(BGPOpenMessage));
}

BGPOpenMessage::BGPOpenMessage(uint32_t my_asn, uint16_t hold_time, uint32_t bgp_id) {
    memset(this, 0, sizeof(BGPOpenMessage));
    this->version = 4;
    this->set4BAsn(my_asn);
    this->hold_time = hold_time;
    this->bgp_id = bgp_id;
}

void BGPOpenMessage::set4BAsn(uint32_t my_asn) {
    this->my_asn = my_asn > 65535 ? 23456 : my_asn;
    this->remove4BAsn();

    if (!this->opt_parms) this->opt_parms = new std::vector<BGPOptionalParameter*>;
    auto param = new BGPOptionalParameter;
    auto capa = new BGPCapability;
    auto caps = new std::vector<BGPCapability*>;

    param->type = 2;
    param->length = 6;
    param->capabilities = caps;

    capa->code = 65;
    capa->length = 4;
    capa->as4_support = true;
    capa->my_asn = my_asn;

    caps->push_back(capa);

    this->opt_parms->push_back(param);
}

void BGPOpenMessage::remove4BAsn() {
    if (!this->opt_parms) return;

    auto params = this->opt_parms;
    std::for_each(params->begin(), params->end(), [](BGPOptionalParameter *param){
        if (param->type != 2 || !param->capabilities) return false;
        auto caps = param->capabilities;
        auto as4_cap = std::find_if(caps->begin(), caps->end(), [](BGPCapability *cap) {
            return cap->code == 65;
        });
        if (as4_cap != caps->end()) caps->erase(as4_cap);
        return true;
    });
}

uint32_t BGPOpenMessage::getAsn() {
    if (!this->opt_parms) return this->my_asn;
    auto params = this->opt_parms;
    uint32_t my_asn = this->my_asn;
    std::for_each(params->begin(), params->end(), [&my_asn](BGPOptionalParameter *param){
        if (param->type != 2 || !param->capabilities) return false;
        auto caps = param->capabilities;
        auto as4_cap = std::find_if(caps->begin(), caps->end(), [](BGPCapability *cap) {
            return cap->code == 65;
        });
        if (as4_cap != caps->end()) my_asn = (*as4_cap)->my_asn;
        return true;
    });

    return my_asn;
}

BGPPathAttribute* BGPUpdateMessage::getAttrib(uint8_t attrib_type) {
    if (!this->path_attribute) return NULL;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [attrib_type](BGPPathAttribute *attr) {
        return attr->type == attrib_type;
    });

    if (attr != attrs->end()) return *attr;
    else return NULL;
}

void BGPUpdateMessage::addAttrib(BGPPathAttribute *attrib) {
    if (!this->path_attribute) this->path_attribute = new std::vector<BGPPathAttribute*>;
    this->path_attribute->push_back(attrib);
}

uint32_t BGPUpdateMessage::getNexthop() {
    auto attr = this->getAttrib(3);
    return attr ? attr->next_hop : 0;
}

void BGPUpdateMessage::setNexthop(uint32_t nexthop) {
    auto attr = this->getAttrib(3);

    if (attr) attr->next_hop = nexthop;
    else {
        auto attr = new BGPPathAttribute;
        attr->type = 3;
        attr->length = 4;
        attr->transitive = true;
        attr->next_hop = nexthop;
        this->addAttrib(attr);
    }
}

std::vector<uint32_t>* BGPUpdateMessage::getAsPath() {
    if (!this->path_attribute) return NULL;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [](BGPPathAttribute *attr) {
        return attr->type == 17 || attr->type == 2;
    });

    if (attr == attrs->end()) return NULL;
    
    std::vector<uint32_t>* path;
    while (attr != attrs->end()) {
        if ((*attr)->type == 17) return (*attr)->as4_path->path;
        if ((*attr)->type == 2) path = (*attr)->as_path->path;
        attr++;
    }
    return path;
}

void BGPUpdateMessage::setAsPath(std::vector<uint32_t>* path, bool peer_as4_ok) {
    if (!this->path_attribute) this->path_attribute = new std::vector<BGPPathAttribute*>;
    auto attrs = this->path_attribute;
    attrs->erase(std::find_if(attrs->begin(), attrs->end(), [](BGPPathAttribute *attr) {
        return attr->type == 17 || attr->type == 2;
    }), attrs->end());

    if (peer_as4_ok) {
        auto n_attr = new BGPPathAttribute;
        auto n_path = new BGPASPath;
        n_path->type = 2;
        n_path->length = path->size();
        n_path->path = path;

        n_attr->type = 2;
        n_attr->transitive = true;
        n_attr->as_path = n_path;
        attrs->push_back(n_attr);
    } else {
        auto n_attr = new BGPPathAttribute;
        auto n_path = new BGPASPath;
        auto n_attr_as2 = new BGPPathAttribute;
        auto n_path_as2 = new BGPASPath;

        auto max_as = std::max_element(path->begin(), path->end());

        if (max_as == path->end()) return; // WTF?

        n_path->type = 17;
        n_path->length = path->size();
        n_path->path = path;

        n_attr->transitive = true;
        n_attr->optional = true;
        n_attr->as4_path = n_path;

        n_path_as2->path = (*max_as > 65535) ? new std::vector<uint32_t> (path->size(), 23456) : path;

        n_attr_as2->type = 2;
        n_attr_as2->transitive = true;
        n_attr_as2->as_path = n_path_as2;
        
        attrs->push_back(n_attr_as2);
        attrs->push_back(n_attr);
    }

}

uint8_t BGPUpdateMessage::getOrigin() {
    auto attr = this->getAttrib(1);
    return attr ? attr->origin : 0; // TODO not 0 when not found
}

void BGPUpdateMessage::setOrigin(uint8_t origin) {
    auto attr = this->getAttrib(1);

    if (attr) attr->origin = origin;
    else {
        auto n_attr = new BGPPathAttribute;
        n_attr->type = 1;
        n_attr->origin = origin;
        n_attr->transitive = true;
        this->addAttrib(n_attr);
    }
}

uint32_t BGPUpdateMessage::getMed() {
    auto attr = this->getAttrib(4);
    return attr ? attr->med : 0; // TODO not 0
}

void BGPUpdateMessage::setMed(uint32_t med) {
    auto attr = this->getAttrib(4);
    if (attr) attr->med = med;
    else {
        auto n_attr = new BGPPathAttribute;
        n_attr->type = 4;
        n_attr->med = med;
        n_attr->optional = true;
        this->addAttrib(n_attr);
    }
}

uint32_t BGPUpdateMessage::getLocalPref() {
    auto attr = this->getAttrib(5);
    return attr ? attr->local_pref : 0; // TODO not 0
}

void BGPUpdateMessage::setLocalPref(uint32_t local_pref) {
    auto attr = this->getAttrib(5);
    if (attr) attr->local_pref = local_pref;
    else {
        auto n_attr = new BGPPathAttribute;
        n_attr->type = 5;
        n_attr->local_pref = local_pref;
        n_attr->optional = true;
        this->addAttrib(n_attr);
    }
}

void BGPUpdateMessage::addPrefix(uint32_t prefix, uint8_t length, bool is_withdraw) {
    auto route = new BGPRoute;
    route->prefix = prefix;
    route->length = length;
    if (is_withdraw) {
        if (!this->withdrawn_routes) this->withdrawn_routes = new std::vector<BGPRoute*>;
        this->withdrawn_routes->push_back(route);
    } else {
        if (!this->nlri) this->nlri = new std::vector<BGPRoute*>;
        this->nlri->push_back(route);
    }
}

}
