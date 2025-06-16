#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_RULES 100

typedef struct {
    uint32_t src_ip;
    uint32_t src_wildcard;
    uint32_t dst_ip;
    uint32_t dst_wildcard;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    int action; // 1 = permit, 0 = deny
} ACL_RULE;

ACL_RULE acl_rules[MAX_RULES];
int rule_count = 0;

void print_acl_rule(const ACL_RULE* rule) {
    char sip[INET_ADDRSTRLEN], swc[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN], dwc[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &rule->src_ip, sip, sizeof(sip));
    inet_ntop(AF_INET, &rule->src_wildcard, swc, sizeof(swc));
    inet_ntop(AF_INET, &rule->dst_ip, dip, sizeof(dip));
    inet_ntop(AF_INET, &rule->dst_wildcard, dwc, sizeof(dwc));

    printf("Rule %d: SRC: %s %s, DST: %s %s, PROTO: %d, SPORT: %d, DPORT: %d, ACTION: %s\n",
        rule_count,
        sip, swc,
        dip, dwc,
        rule->protocol,
        rule->src_port,
        rule->dst_port,
        rule->action ? "PERMIT" : "DENY");
}

void get_user_input() {
    if (rule_count >= MAX_RULES) {
        printf("Max rules reached.\n");
        return;
    }

    char src_ip[16], src_wc[16], dst_ip[16], dst_wc[16];
    int protocol, action, sport, dport;

    printf("\nEntering rule %d:\n", rule_count + 1);
    printf("Enter Source IP: ");
    scanf("%15s", src_ip);
    printf("Enter Source Wildcard Mask (e.g. 0.0.0.255): ");
    scanf("%15s", src_wc);
    printf("Enter Destination IP: ");
    scanf("%15s", dst_ip);
    printf("Enter Destination Wildcard Mask (e.g. 0.0.0.255): ");
    scanf("%15s", dst_wc);
    printf("Enter Protocol (1=ICMP, 6=TCP, 17=UDP, 0=Any): ");
    scanf("%d", &protocol);
    printf("Enter Source Port (0 if not needed): ");
    scanf("%d", &sport);
    printf("Enter Destination Port (0 if not needed): ");
    scanf("%d", &dport);
    printf("Enter Action (1=Permit, 0=Deny): ");
    scanf("%d", &action);

    ACL_RULE *rule = &acl_rules[rule_count];
    rule->src_ip = inet_addr(src_ip);
    rule->src_wildcard = inet_addr(src_wc);
    rule->dst_ip = inet_addr(dst_ip);
    rule->dst_wildcard = inet_addr(dst_wc);
    rule->protocol = protocol;
    rule->src_port = sport;
    rule->dst_port = dport;
    rule->action = action;

    print_acl_rule(rule);
    rule_count++;
}

void process_packet(const u_char* packet, struct pcap_pkthdr* header,
                    pcap_dumper_t* permit_dump, pcap_dumper_t* deny_dump) {
    const struct ip *ip_hdr = (const struct ip*)(packet + 14);
    if (ip_hdr->ip_v != 4) return;

    uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr);
    uint32_t dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
    uint8_t protocol = ip_hdr->ip_p;
    uint16_t src_port = 0, dst_port = 0;

    const u_char* transport = packet + 14 + ip_hdr->ip_hl * 4;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)transport;
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)transport;
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
    }

    for (int i = 0; i < rule_count; ++i) {
        ACL_RULE *r = &acl_rules[i];

        if (r->protocol != 0 && r->protocol != protocol) continue;

        // WILDCARD match logic (Cisco-style)
        if ((src_ip & ~ntohl(r->src_wildcard)) != (ntohl(r->src_ip) & ~ntohl(r->src_wildcard))) continue;
        if ((dst_ip & ~ntohl(r->dst_wildcard)) != (ntohl(r->dst_ip) & ~ntohl(r->dst_wildcard))) continue;

        if (r->src_port && r->src_port != src_port) continue;
        if (r->dst_port && r->dst_port != dst_port) continue;

        if (r->action == 1)
            pcap_dump((u_char*)permit_dump, header, packet);
        else
            pcap_dump((u_char*)deny_dump, header, packet);
        return;
    }

    // Default deny
    pcap_dump((u_char*)deny_dump, header, packet);
}

int main() {
    char input_pcap[256];
    printf("Enter input PCAP filename (e.g., input.pcap): ");
    scanf("%s", input_pcap);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(input_pcap, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open input file: %s\n", errbuf);
        return 1;
    }

    pcap_t *pcap_dead = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *permit_dump = pcap_dump_open(pcap_dead, "permitted.pcap");
    pcap_dumper_t *deny_dump = pcap_dump_open(pcap_dead, "denied.pcap");

    int num_rules;
    printf("Enter number of ACL rules: ");
    scanf("%d", &num_rules);

    for (int i = 0; i < num_rules; ++i) {
        get_user_input();
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    while (pcap_next_ex(handle, &header, &packet) == 1) {
        process_packet(packet, header, permit_dump, deny_dump);
    }

    pcap_dump_close(permit_dump);
    pcap_dump_close(deny_dump);
    pcap_close(pcap_dead);
    pcap_close(handle);

    printf("✅ Packet filtering complete. Check permitted.pcap and denied.pcap.\n");
    return 0;
}
