#include "include/rtable.h"

void read_rtable(struct route_table_entry *rtable, int size, char *file_name) {

    FILE *input;
    input = fopen(file_name, "r");
    if(!input) {
        return;
    }

    char *line = NULL;
    size_t len = 0;
    for(int i = 0; i < size; i++) {
        struct in_addr addr;
        getline(&line, &len, input);

        char *tok = strtok(line, " ");
        inet_aton(tok, &addr);
        rtable[i].prefix = addr.s_addr;

        tok = strtok(NULL, " ");
        inet_aton(tok, &addr);
        rtable[i].next_hop = addr.s_addr;

        tok = strtok(NULL, " ");
        inet_aton(tok, &addr);
        rtable[i].mask = addr.s_addr;

        tok = strtok(NULL, "\n");
        int interface = atoi(tok);
        rtable[i].interface = interface;
    }

    fclose(input);
}

int compare(const void *a, const void *b) {

    if(((struct route_table_entry *)a)->prefix == ((struct route_table_entry*)b)->prefix) {
        return ((struct route_table_entry *)b)->mask - ((struct route_table_entry *)a)->mask;
    }
    return ((struct route_table_entry *)a)->prefix - ((struct route_table_entry*)b)->prefix;
}

void sort_rtable(struct route_table_entry *rtable, int size) {
    qsort(rtable, size, sizeof(struct route_table_entry), compare);
}

struct route_table_entry *get_best_route(struct route_table_entry *rtable, int rtable_size, u_int32_t dest_ip) {
    int low = 0;
    int high = rtable_size;
    struct route_table_entry *best = NULL;

    while (low <= high) {
        int mid = low + ((high - low) / 2);

        if((rtable[mid].prefix) == (dest_ip & rtable[mid].mask)) {
            best = &rtable[mid];
            while(mid > 0 &&
                  rtable[mid].prefix == rtable[mid - 1].prefix &&
                  rtable[mid].mask <= rtable[mid - 1].mask) {

                mid--;
                best = &rtable[mid];
            }
            return best;
        }

        if(rtable[mid].prefix > (dest_ip & rtable[mid].mask)) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    return best;
}

