#include "lib.h"
#include "protocols.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#define MAX_ROUTE_ENTRIES 100000
#define MAX_ARP_ENTRIES 10
#define ICMP_HEADER_SIZE sizeof(struct icmp_hdr)
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DESTINATION_UNREACHABLE 3
#define IP_PROTOCOL_ICMP 1

typedef struct {
    void **items;
    size_t size;
    size_t capacity;
} buffer_t;

buffer_t buffer_create() {
    buffer_t buf = { .items = NULL, .size = 0, .capacity = 0 };
    return buf;
}

void buffer_destroy(buffer_t *buf) {
    free(buf->items);
    buf->items = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

void buffer_push(buffer_t *buf, void *item) {
    if (buf->size == buf->capacity) {
        buf->capacity = buf->capacity ? buf->capacity * 2 : 4;
        buf->items = realloc(buf->items, buf->capacity * sizeof(void *));
    }
    buf->items[buf->size++] = item;
}

void *buffer_pop(buffer_t *buf, size_t index) {
    if (index >= buf->size) return NULL;
    void *item = buf->items[index];
    for (size_t i = index; i < buf->size - 1; ++i) {
        buf->items[i] = buf->items[i + 1];
    }
    buf->size--;
    return item;
}

int buffer_empty(buffer_t *buf) {
    return buf->size == 0;
}

struct route_table_entry *routing_table;
int routing_table_size;

struct arp_table_entry arp_table[MAX_ARP_ENTRIES];
int arp_table_size;

buffer_t packet_buffer;

int route_comparator(const void *a, const void *b);
struct route_table_entry *longest_prefix_match(uint32_t dest_ip);
struct arp_table_entry *get_arp_entry(uint32_t ip);
void send_icmp_error_packet(char *packet, int size, int iface, uint8_t type, uint8_t code);
void process_arp_reply(struct arp_hdr *arp);
void process_arp_request(char *buf, size_t size, int iface);
void enqueue_packet_for_arp(char *buf, size_t size, struct route_table_entry *route);
void try_forward_packet(char *buf, size_t size, int iface);
void handle_icmp_echo_reply(char *buf, int size, int iface);
int is_packet_for_me(struct ether_hdr *eth, int iface);

int route_comparator(const void *a, const void *b) {
    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    uint32_t mask1 = ntohl(entry1->mask);
    uint32_t mask2 = ntohl(entry2->mask);

    if (mask1 != mask2)
        return (mask2 - mask1);

    uint32_t prefix1 = ntohl(entry1->prefix);
    uint32_t prefix2 = ntohl(entry2->prefix);

    return (prefix1 > prefix2) - (prefix1 < prefix2);
}

struct route_table_entry *longest_prefix_match(uint32_t dest_ip) {
    struct route_table_entry *match = NULL;
    int low = 0, high = routing_table_size - 1;
    
    while (low <= high) {
        int mid = high - (high - low) / 2;
        uint32_t prefix = ntohl(routing_table[mid].prefix);
        uint32_t mask = ntohl(routing_table[mid].mask);
        uint32_t masked_ip = ntohl(dest_ip) & mask;
        
        if (masked_ip == prefix) {
            match = &routing_table[mid];
            low = mid + 1;
        } else if (prefix > masked_ip) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    
    return match;
}

struct arp_table_entry *get_arp_entry(uint32_t ip) {
    int i = 0;
    while (i < arp_table_size) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
        i++;
    }
    return NULL;
}

int is_packet_for_me(struct ether_hdr *eth, int iface) {
    uint8_t mac[6];
    const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    get_interface_mac(iface, mac);

    int is_unicast = memcmp(eth->ethr_dhost, mac, 6) == 0;
    int is_broadcast = memcmp(eth->ethr_dhost, broadcast_mac, 6) == 0;

    return is_unicast || is_broadcast;
}

void build_icmp_error_packet(char *reply_buf, const char *received_packet, int iface,
    uint8_t icmp_type, uint8_t icmp_code) {
const struct ether_hdr *recv_eth = (const struct ether_hdr *)received_packet;
const struct ip_hdr *recv_ip = (const struct ip_hdr *)(received_packet + sizeof(struct ether_hdr));

struct ether_hdr *eth = (struct ether_hdr *)reply_buf;
struct ip_hdr *ip = (struct ip_hdr *)(reply_buf + sizeof(struct ether_hdr));
struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + sizeof(struct ip_hdr));
uint8_t *icmp_payload = (uint8_t *)icmp + ICMP_HEADER_SIZE;

memcpy(eth, recv_eth, sizeof(struct ether_hdr));
memcpy(eth->ethr_shost, recv_eth->ethr_dhost, 6);               
get_interface_mac(iface, eth->ethr_dhost);                      

memcpy(ip, recv_ip, sizeof(struct ip_hdr));
ip->tot_len = htons(sizeof(struct ip_hdr) + ICMP_HEADER_SIZE + 8);
ip->ttl = 64;
ip->proto = IP_PROTOCOL_ICMP;

uint32_t orig_src = ip->source_addr;
ip->source_addr = ip->dest_addr;
ip->dest_addr = orig_src;

ip->checksum = 0;
ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

icmp->mtype = icmp_type;
icmp->mcode = icmp_code;
icmp->check = 0;

memcpy(icmp_payload, recv_ip, sizeof(struct ip_hdr) + 8);
icmp->check = htons(checksum((uint16_t *)icmp, ICMP_HEADER_SIZE + sizeof(struct ip_hdr) + 8));
}

void send_icmp_error_packet(char *packet, int size, int iface, uint8_t type, uint8_t code) {
    char reply[sizeof(struct ether_hdr) + sizeof(struct ip_hdr) +
               ICMP_HEADER_SIZE + sizeof(struct ip_hdr) + 8];

    build_icmp_error_packet(reply, packet, iface, type, code);

    struct ip_hdr *ip = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));
    size_t total_len = sizeof(struct ether_hdr) + ntohs(ip->tot_len);

    send_to_link(total_len, reply, iface);
}

void process_arp_reply(struct arp_hdr *arp) {
    if (!get_arp_entry(arp->sprotoa) && arp_table_size < MAX_ARP_ENTRIES) {
        memcpy(arp_table[arp_table_size].mac, arp->shwa, 6);
        arp_table[arp_table_size++].ip = arp->sprotoa;
    }

    for (size_t i = 0; i < packet_buffer.size;) {
        void *raw = packet_buffer.items[i];
        size_t size = *((size_t *)raw);
        char *pkt = (char *)raw + sizeof(size_t);
        
        struct ip_hdr *ip = (struct ip_hdr *)(pkt + sizeof(struct ether_hdr));
        struct route_table_entry *route = longest_prefix_match(ip->dest_addr);
        
        if (route) {
            struct arp_table_entry *arp_entry = get_arp_entry(route->next_hop);
            
            if (arp_entry) {
                struct ether_hdr *eth = (struct ether_hdr *)pkt;
                get_interface_mac(route->interface, eth->ethr_shost);
                memcpy(eth->ethr_dhost, arp_entry->mac, 6);
                send_to_link(size, pkt, route->interface);

                free(raw);
                buffer_pop(&packet_buffer, i);
            } else {
                i++;
            }
        } else {
            free(raw);
            buffer_pop(&packet_buffer, i);
        }
    }
}

void craft_arp_reply(struct arp_hdr *arp, struct ether_hdr *eth, int iface) {
    uint8_t my_mac[6];
    get_interface_mac(iface, my_mac);

    memcpy(arp->thwa, arp->shwa, ETH_ALEN);
    memcpy(arp->shwa, my_mac, ETH_ALEN);

    uint32_t temp_ip = arp->sprotoa;
    arp->sprotoa = arp->tprotoa;
    arp->tprotoa = temp_ip;

    memcpy(eth->ethr_dhost, eth->ethr_shost, ETH_ALEN);
    memcpy(eth->ethr_shost, my_mac, ETH_ALEN);
}

void process_arp_request(char *buf, size_t size, int iface) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    arp->opcode = htons(ARP_OP_REPLY);
    craft_arp_reply(arp, eth, iface);
    send_to_link(size, buf, iface);
}

void enqueue_packet_for_arp(char *buf, size_t size, struct route_table_entry *route) {
    size_t total_size = sizeof(size_t) + size;
    char *copy = malloc(total_size);
    if (!copy) return;
    
    memcpy(copy, &size, sizeof(size_t));
    memcpy(copy + sizeof(size_t), buf, size);
    buffer_push(&packet_buffer, copy);

    struct ether_hdr eth = { 
        .ethr_type = htons(ETHERNET_TYPE_ARP) 
    };
    memset(eth.ethr_dhost, 0xFF, 6);
    get_interface_mac(route->interface, eth.ethr_shost);

    struct arp_hdr arp = {
        .hw_type = htons(1),         
        .proto_type = htons(0x0800),
        .hw_len = 6,            
        .proto_len = 4,          
        .opcode = htons(ARP_OP_REQUEST),
        .sprotoa = inet_addr(get_interface_ip(route->interface)),
        .tprotoa = route->next_hop
    };
    get_interface_mac(route->interface, arp.shwa);
    memset(arp.thwa, 0, 6);

    char packet[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
    memcpy(packet, &eth, sizeof(eth));
    memcpy(packet + sizeof(eth), &arp, sizeof(arp));
    send_to_link(sizeof(packet), packet, route->interface);
}

void try_forward_packet(char *buf, size_t size, int iface) {
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    uint16_t original_ck = ip->checksum;
    ip->checksum = 0;
    if (htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr))) != original_ck) {
        return;
    }

    if (ip->ttl <= 1) {
        send_icmp_error_packet(buf, size, iface, ICMP_TIME_EXCEEDED, 0);
        return;
    }

    ip->ttl--;

    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    struct route_table_entry *route = longest_prefix_match(ip->dest_addr);
    if (!route) {
        send_icmp_error_packet(buf, size, iface, ICMP_DESTINATION_UNREACHABLE, 0);
        return;
    }

    struct arp_table_entry *arp = get_arp_entry(route->next_hop);
    if (!arp) {
        enqueue_packet_for_arp(buf, size, route);
        return;
    }

    struct ether_hdr *eth = (struct ether_hdr *)buf;
    get_interface_mac(route->interface, eth->ethr_shost);
    memcpy(eth->ethr_dhost, arp->mac, 6);
    send_to_link(size, buf, route->interface);
}

void handle_icmp_echo_reply(char *buf, int size, int iface) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + ip->ihl * 4);

    uint8_t src_mac[6];
    memcpy(src_mac, eth->ethr_shost, 6);
    get_interface_mac(iface, eth->ethr_shost);
    memcpy(eth->ethr_dhost, src_mac, 6);

    uint32_t src_ip = ip->source_addr;
    ip->source_addr = ip->dest_addr;
    ip->dest_addr = src_ip;

    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    icmp->mtype = ICMP_ECHO_REPLY;
    icmp->mcode = 0;
    icmp->check = 0;

    size_t icmp_len = size - sizeof(struct ether_hdr) - ip->ihl * 4;
    icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

    send_to_link(size, buf, iface);
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    init(argv + 2, argc - 2);

    routing_table = malloc(MAX_ROUTE_ENTRIES * sizeof(struct route_table_entry));
    if (!routing_table) {
        fprintf(stderr, "\n");
        return 1;
    }
    
    routing_table_size = read_rtable(argv[1], routing_table);
    qsort(routing_table, routing_table_size, sizeof(struct route_table_entry), route_comparator);

    packet_buffer = buffer_create();
    arp_table_size = 0;

    while (1) {
        int iface;
        size_t size;

        iface = recv_from_any_link(buf, &size);
        DIE(iface < 0, "");
        
        struct ether_hdr *eth = (struct ether_hdr *)buf;

        if (!is_packet_for_me(eth, iface)) {
            continue;
        }

        if (ntohs(eth->ethr_type) == ETHERNET_TYPE_ARP) {
            struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
            
            if (ntohs(arp->opcode) == ARP_OP_REQUEST) {
                process_arp_request(buf, size, iface);
            } else if (ntohs(arp->opcode) == ARP_OP_REPLY) {
                process_arp_reply(arp);
            }
        } else if (ntohs(eth->ethr_type) == ETHERNET_TYPE_IP) {
            struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

            if (ip->proto == IP_PROTOCOL_ICMP && 
                ip->dest_addr == inet_addr(get_interface_ip(iface))) {
                
                struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + ip->ihl * 4);
                
                if (icmp->mtype == ICMP_ECHO_REQUEST) {
                    handle_icmp_echo_reply(buf, size, iface);
                }
            } else {
                try_forward_packet(buf, size, iface);
            }
        }
    }

    buffer_destroy(&packet_buffer);
    free(routing_table);
    
    return 0;
}