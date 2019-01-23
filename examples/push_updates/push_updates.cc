#include "../../src/libbgp.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

#define MY_ASN 65000
#define MY_BGP_ID "172.31.0.2"
#define NEXTHOP "172.31.0.2"

char* print_ip(uint32_t ip)
{
    unsigned char bytes[4];
    char *ip_str = (char *) malloc(16);
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    sprintf(ip_str, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return ip_str;
}

int main (void) {
    int fd_sock, fd_conn;
    struct sockaddr_in server_addr, client_addr;
    uint8_t *buffer = (uint8_t *) malloc(4096);
    bool update_sent = false;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(179);

    fd_sock = socket(AF_INET, SOCK_STREAM, 0);

    int ret = bind(fd_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret < 0) return 1;
    listen(fd_sock, 1);

    socklen_t caddr_len = sizeof(client_addr);
    fd_conn = accept(fd_sock, (struct sockaddr *) &client_addr, &caddr_len);

    while (1) {
        ret = read(fd_conn, buffer, 4096);
        if (ret < 0) return 1;
        auto bgp_pkt = new LibBGP::BGPPacket(buffer);

        if (bgp_pkt->type == 1) { // recevied an OPEN
            if (!bgp_pkt->open) {
                printf("received an OPEN message, but failed to parse, ignore.");
                continue;
            }
            auto open_msg = bgp_pkt->open;
            printf("OPEN from AS%d, ID: %s\n", open_msg->getAsn(), print_ip(open_msg->bgp_id));
            //print_ip(open_msg->bgp_id);
            //printf("\n");

            // reply with open
            auto reply_msg = new LibBGP::BGPPacket;
            reply_msg->type = 1; // type = OPEN

            uint32_t my_bgp_id;
            inet_pton(AF_INET, MY_BGP_ID, &my_bgp_id);

            reply_msg->open = new LibBGP::BGPOpenMessage(MY_ASN, 60, my_bgp_id); // ASN = MY_ASN, hold = 60, ID = my_bgp_id

            int len = reply_msg->write(buffer);
            write(fd_conn, buffer, len); // write OPEN

            delete reply_msg;
        }

        if (bgp_pkt->type == 4) { // KEEPALIVE
            printf("KEEPALIVE received.\n");
            auto reply_msg = new LibBGP::BGPPacket;
            reply_msg->type = 4; // TYPE = KEEPALIVE

            int len = reply_msg->write(buffer);
            write(fd_conn, buffer, len); // write KEEPALIVE

            delete reply_msg;

            if (!update_sent) { // write update once open_cfm KEEPALIVE
                printf("Sending update 10.114.0.0/16 to peer.\n");
                update_sent = true;
                auto update_msg = new LibBGP::BGPPacket;
                auto update = new LibBGP::BGPUpdateMessage;
                update_msg->type = 2; // UPDATE
                uint32_t prefix_add, nexthop;
                inet_pton(AF_INET, NEXTHOP, &nexthop);
                inet_pton(AF_INET, "10.114.0.0", &prefix_add);
                update->setNexthop(nexthop);
                update->addPrefix(prefix_add, 16, false); // (prefix, len, is_withdraw)
                update->setOrigin(0);
                auto as_path = new std::vector<uint32_t> {MY_ASN};
                update->setAsPath(as_path, true); // (path, is_4b)
                update_msg->update = update;
                len = update_msg->write(buffer);
                write(fd_conn, buffer, len);

                delete update_msg;
            }
        }

        delete bgp_pkt;
    }
}
