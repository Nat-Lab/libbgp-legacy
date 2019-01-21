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
        auto as4_cap = std::find_if(caps->begin(), caps->end(), [](BGPCapability *cap) {
            return cap->code == 65;
        });
        if (as4_cap != caps->end()) caps->erase(as4_cap);
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
    });

    return my_asn;
}

uint32_t BGPUpdateMessage::getNexthop() {

}

void BGPUpdateMessage::setNexthop(uint32_t nexthop) {

}

std::vector<uint32_t>* BGPUpdateMessage::getAsPath() {

}

void BGPUpdateMessage::setAsPath(std::vector<uint32_t>* path) {

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