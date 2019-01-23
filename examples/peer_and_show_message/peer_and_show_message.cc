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
#define MY_BGP_ID "172.32.0.2"

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

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(179);

    fd_sock = socket(AF_INET, SOCK_STREAM, 0);

    bind(fd_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
    listen(fd_sock, 1);

    socklen_t caddr_len = sizeof(client_addr);
    fd_conn = accept(fd_sock, (struct sockaddr *) &client_addr, &caddr_len);

    while (1) {
        read(fd_conn, buffer, 4096);
        auto bgp_pkt = new LibBGP::BGPPacket(buffer);

        if (bgp_pkt->type == 1) { // recevied an OPEN
            if (!bgp_pkt->open) {
                printf("received an OPEN message, but failed to parse, ignore.");
                continue;
            }
            auto open_msg = bgp_pkt->open;
            printf("OPEN from AS%d, ID: %s.\n", open_msg->getAsn(), print_ip(open_msg->bgp_id));

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

        if (bgp_pkt->type == 2) { // UPDATE
             if (!bgp_pkt->update) {
                printf("received an UPDATE message, but failed to parse, ignore.");
                continue;
            }

            auto update_msg = bgp_pkt->update;
            auto as_path = update_msg->getAsPath();
            auto routes_drop = update_msg->withdrawn_routes;
            auto routes_add = update_msg->nlri;
            auto next_hop = update_msg->getNexthop();

            printf("UPDATE received");

            if (next_hop) printf(", next_hop: %s", print_ip(next_hop));

            if (as_path) {
                printf(", as_path:");
                for (int i = 0; i < as_path->size(); i++) printf(" %d", as_path->at(i));
            }

            if (routes_drop->size() > 0) {
                printf(", withdrawn_routes:");
                for (int i = 0; i < routes_drop->size(); i++)
                    printf(" %s/%d", print_ip(routes_drop->at(i)->prefix), routes_drop->at(i)->length);
            }

            if (routes_add->size() > 0) {
                printf(", nlri:");
                for (int i = 0; i < routes_add->size(); i++)
                    printf(" %s/%d", print_ip(routes_add->at(i)->prefix), routes_add->at(i)->length);
            }

            printf(".\n");
        }

        if (bgp_pkt->type == 4) { // KEEPALIVE
            printf("KEEPALIVE received.\n");
            auto reply_msg = new LibBGP::BGPPacket;
            reply_msg->type = 4; // TYPE = KEEPALIVE

            int len = reply_msg->write(buffer);
            write(fd_conn, buffer, len); // write KEEPALIVE

            delete reply_msg;
        }

        delete bgp_pkt;
    }
}
