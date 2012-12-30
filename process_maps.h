#ifndef PROCESS_MAPS_H
#define PROCESS_MAPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "../lib/include/sblist.h"

typedef enum {
	MDP_R = 1 << 0,
	MDP_W = 1 << 1,
	MDP_X = 1 << 2,
	MDP_P = 1 << 3, //private (copy on write)
	MDP_S = 1 << 4, //shared
} map_data_perms;

typedef struct {
	void* start;
	void* end;
} map_data_address;

typedef struct {
	unsigned char major;
	unsigned char minor;
} map_data_dev;

typedef struct {
	map_data_address address;
	uint64_t inode;
	uint64_t offset;
	char* pathname;
	map_data_dev dev;
	unsigned char perms;
} map_data;

/* returns a sblist (or NULL) containing map_data members by parsing /proc/pid/maps */
sblist* process_maps_get(pid_t pid);
/* free the memory claimed by process_maps_get */
void process_maps_free(sblist* maps);
/* generates a readable string from a permission byte */
void process_maps_perms_str(unsigned char perms, char* outbuf5);
/* returns a mapdata* for the map the addr is contained in, or NULL */
map_data* find_map_for_addr(sblist* maps, void* addr);
/* returns size of a mapping */
size_t process_map_size(map_data* map);

#ifdef __cplusplus
}
#endif

//RcB: DEP "process_maps.c"

#endif
