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

BGPPathAttribute* BGPUpdateMessage::getAttrib(uint8_t attrib_type) {
    if (!this->path_attribute) return NULL;
    auto attrs = this->path_attribute;
    auto attr = std::find_if(attrs->begin(), attrs->end(), [attrib_type](auto attr) {
        return attr->type == attrib_type;
    });

    if (attr != attrs->end()) return *attr;
    else return NULL;
}

void BGPUpdateMessage::addAttrib(BGPPathAttribute *attrib) {
    if (!this->path_attribute) this->path_attribute = new std::vector<BGPPathAttribute*>;
    else this->path_attribute->push_back(attrib);
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
    auto attr = this->getAttrib(as4 ? 17 : 2);

    if (attr) {
        if (as4) attr->as4_path->path = path; // maybe do delete? 
        else attr->as_path->path = path;
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

        this->addAttrib(n_attr);
    }

    if (as4) {
        auto as2_path = new std::vector<uint32_t> (path->size(), 23456);
        this->setAsPath(as2_path, false);
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
        this->addAttrib(n_attr);
    }
}

}