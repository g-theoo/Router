#ifndef RTABLE_H
#define RTABLE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct route_table_entry {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} __attribute__((packed));

void read_rtable(struct route_table_entry *rtable, int size, char *file_name);
int compare(const void *a, const void *b);
void sort_rtable(struct route_table_entry *rtable, int size);
struct route_table_entry *get_best_route(struct route_table_entry *rtable, int rtable_size, u_int32_t dest_ip);

#endif