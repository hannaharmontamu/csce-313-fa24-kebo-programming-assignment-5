#include "common.h"

int main()
{
    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    ipheader *ip = (ipheader *)buffer;
    udpheader *udp = (udpheader *)(buffer + sizeof(ipheader));

    // add data
    char *data = (char *)udp + sizeof(udpheader);
    int data_len = strlen(CLIENT_IP);
    strncpy(data, CLIENT_IP, data_len);

    // create udp header
    udp->udp_sport = htons(CLIENT_PORT);    // source port
    udp->udp_dport = htons(SERVER_PORT);    // dest port
    udp->udp_ulen = htons(sizeof(udpheader) + data_len);    // UDP length
    udp->udp_sum = 0; // optional in UDP

    // create ip header
    ip->iph_ver = 4;    // IPv4
    ip->iph_ihl = 5;    // IP header length
    ip->iph_tos = 0;    // type of service
    ip->iph_len = htons(sizeof(ipheader) + sizeof(udpheader) + data_len);
    ip->iph_ident = htons(54321);   // identifier
    ip->iph_ttl = 64;   // time to live
    ip->iph_protocol = IPPROTO_UDP; // protocol
    ip->iph_sourceip.s_addr = inet_addr(SPOOF_IP);  // spoofed source ip
    ip->iph_destip.s_addr = inet_addr(SERVER_IP);   // dest ip
    ip->iph_chksum = 0; // calculated later

    // send packet
    send_raw_ip_packet(ip);

    printf("Spoofed packet sent from %s to %s\n", SPOOF_IP, SERVER_IP);
    return 0;
}