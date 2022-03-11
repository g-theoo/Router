#include <queue.h>
#include "skel.h"
#include "rtable.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;

    int rtable_size = count_lines(argv[1]);
    int arp_table_size = count_lines("arp_table.txt");

    struct route_table_entry *rtable =
            (struct route_table_entry*)malloc(rtable_size * sizeof( struct route_table_entry));
    DIE(!rtable, "Failed to create the routing table");
    memset(rtable, 0, (sizeof (struct route_table_entry)));

    //PARSARE SI SORTARE TABELA DE RUTARE
    read_rtable(rtable, rtable_size, argv[1]);
    sort_rtable(rtable, rtable_size);

    //PARSARE TABELA ARP
    struct arp_entry *arp_table = (struct arp_entry*)malloc(arp_table_size * sizeof(struct arp_entry));
    parse_arp_table(arp_table);

	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

        struct ether_header* eth_hdr = (struct ether_header*)m.payload;
        struct iphdr *ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ether_header));

        struct in_addr *destination = (struct in_addr*)malloc(sizeof (struct in_addr));
        inet_aton(get_interface_ip(m.interface), destination);

        //VERIFICARE DACA PACHETUL ESTE PENTRU ROUTER
        if(ip_hdr->daddr == destination->s_addr) {
            struct icmphdr* icmp_hdr = parse_icmp(m.payload);
            if(icmp_hdr != NULL && icmp_hdr->type == ICMP_ECHO) {
                //TRIMITERE ICMP Echo Replay
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
                get_interface_mac(m.interface,eth_hdr->ether_shost);
                send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 0, 0, m.interface, htons(getpid()), 1);
                continue;
            }
        }

        //VERIFICARE TTL
        if(ip_hdr->ttl <= 1) {
            //TRIMITERE ICMP Time Exceeded
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
            get_interface_mac(m.interface,eth_hdr->ether_shost);
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11, 0, m.interface);
            continue;
        }

        //VERIFICARE CHECKSUM
        if(ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
            continue;
        }

        //ACTUALIZARE PACHET (decrementare TTL si recalcularea Checksum-ului)
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

        //GASIRE CEA MAI BUNA RUTA PENTRU PACHET
        struct route_table_entry *best_route = get_best_route(rtable, rtable_size, ip_hdr->daddr);
        if(best_route == NULL) {
            //TRIMITERE ICMP Destination Unreachable in caz ca nu s-a gasit o ruta
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
            get_interface_mac(m.interface,eth_hdr->ether_shost);
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 3, 0, m.interface);
        }

        struct arp_entry *target = get_arp_entry(arp_table, arp_table_size, best_route->next_hop);
        get_interface_mac(best_route->interface, eth_hdr->ether_shost);
        memcpy(eth_hdr->ether_dhost, target->mac, sizeof(target->mac));

        send_packet(best_route->interface, &m);
	}
}
