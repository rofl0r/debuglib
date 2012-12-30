#include <stdio.h>
#include <sys/mman.h>
#include "../process_maps.h"

void msg() {
	printf("sux\n");
}

int main() {
#ifdef MAKE_WRITABLE
	sblist* maps = process_maps_get(getpid());
	map_data* map;
	if(maps) {
		map = find_map_for_addr(maps, (void*) 0x400000);
		if(map) mprotect(map->address.start, process_map_size(map), PROT_READ | PROT_WRITE | PROT_EXEC);
		__asm__("int3");
	}
#endif
	unsigned i;
	for(i = 0; i < 10; i++)
		msg();
	return 0;
}
