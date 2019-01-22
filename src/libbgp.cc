#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include "libbgp.h"
#include <stdio.h>

namespace LibBGP {

BGPOpenMessage::BGPOpenMessage() {}

BGPOpenMessage::BGPOpenMessage(uint32_t my_asn, uint16_t hold_time, uint32_t bgp_id) {
    this->version = 4;
    this->set4BAsn(my_asn);
    this->hold_time = hold_time;
    this->bgp_id = bgp_id;
}

void BGPOpenMessage::set4BAsn(uint32_t my_asn) {
    this->my_asn = my_asn > 65535 ? 23456 : my_asn;
    this->remove4BAsn();

    if (!this->opt_parms) this->opt_parms = new std::vector<BGPOptionalParameter*>;
    auto parms = this->opt_parms;
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
        auto as4_cap = std::find_if(caps->begin(), caps->end(), [](auto cap) {
            return cap->code == 65;
        });
        if (as4_cap != caps->end()) caps->erase(as4_cap);
    });
}

uint32_t BGPOpenMessage::getAsn() {
    if (!this->opt_parms) return this->my_asn;
    auto params = this->opt_parms;
    uint32_t my_asn = this->my_asn;
    std::for_each(params->begin(), params->end(), [&my_asn](auto param){
        if (param->type != 2 || !param->capabilities) return false;
        auto caps = param->capabilities;
        auto as4_cap = std::find_if(caps->begin(), caps->end(), [](auto cap) {
            return cap->code == 65;
        });
        if (as4_cap != caps->end()) my_asn = (*as4_cap)->my_asn;
    });

    return my_asn;
}

uint32_t BGPUpdateMessage::getNexthop() {
    if (!this->path_attribute) return 0;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [](auto attr) {
        return attr->type == 3;
    });

    if (attr != attrs->end()) return (*attr)->next_hop;
    else return 0;
}

void BGPUpdateMessage::setNexthop(uint32_t nexthop) {
    if (!this->path_attribute) this->path_attribute = new std::vector<BGPPathAttribute*>;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [](auto attr) {
        return attr->type == 3;
    });

    if (attr != attrs->end()) (*attr)->next_hop = nexthop;
    else {
        auto attr = new BGPPathAttribute;
        attr->type = 3;
        attr->length = 4;
        attr->transitive = true;
        attr->next_hop = nexthop;

        attrs->push_back(attr);
    }
}

std::vector<uint32_t>* BGPUpdateMessage::getAsPath() {
    if (!this->path_attribute) return NULL;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [](auto attr) {
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

void BGPUpdateMessage::setAsPath(std::vector<uint32_t>* path, bool as4) {
    if (!this->path_attribute) this->path_attribute = new std::vector<BGPPathAttribute*>;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [as4](auto attr) {
        return attr->type == (as4 ? 17 : 2);
    });

    if (attr != attrs->end()) {
        if (as4) (*attr)->as4_path->path = path;
        else (*attr)->as_path->path = path;
    }
    else {
        auto n_attr = new BGPPathAttribute;
        auto n_path = new BGPASPath;
        n_path->type = 2;
        n_path->length = path->size();
        n_path->path = path;

        n_attr->type = (as4 ? 17 : 2);
        n_attr->transitive = true;
        if (as4) n_attr->as4_path = n_path;
        else n_attr->as_path = n_path;

        attrs->push_back(n_attr);
    }
}

uint8_t BGPUpdateMessage::getOrigin() {

}

void BGPUpdateMessage::setOrigin(uint8_t origin) {

}

uint32_t BGPUpdateMessage::getMed() {

}

void BGPUpdateMessage::setMed(uint32_t med) {

}

uint32_t BGPUpdateMessage::getLocalPref() {

}

void BGPUpdateMessage::setLocalPref(uint32_t local_pref) {

}

}