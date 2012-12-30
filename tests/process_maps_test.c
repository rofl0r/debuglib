#include "../process_maps.h"
#include "../debuglib.h"
#include <stdio.h>

int main() {
	sblist* maps = process_maps_get(getpid());
	map_data* map;
	char permbuf[5];
	if(maps) {
		sblist_iter(maps, map) {
			process_maps_perms_str(map->perms, permbuf);
			printf("%p-%p, %s, %d, %d:%d %d, %s\n", 
			map->address.start, map->address.end,
				permbuf, map->offset ,
				map->dev.major, map->dev.minor,
				map->inode, map->pathname ? map->pathname : "");
		}
		sblist_iter(maps, map) {
			printf("<%s>\n", map->pathname ? map->pathname : "");
			if(map->perms & MDP_R)
				dump_ram(map->address.start, map->address.end - map->address.start, 64);
		}
		process_maps_free(maps);
	}
	
	return 0;
}
