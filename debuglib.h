#ifndef DEBUGLIB_H
#define DEBUGLIB_H

#include <stddef.h>
#include <stdlib.h>

#include "process_maps.h"

#include "../lib/include/hashlist.h"

#define BP_INSTR_SIZE_MAX 16
typedef struct {
	void* addr;
	unsigned char map_perms;
	unsigned char bp_instr_size;
	char bp_backup[BP_INSTR_SIZE_MAX];
	int active:1;
} breakpointinfo;

typedef struct {
	hashlist* breakpoints;
	sblist* processmaps;
	int syscall_ret;
} debugger_state;

typedef enum {
	DE_NONE = 0,
	DE_HIT_BP,
	DE_EXIT,
	DE_FORK,
	DE_VFORK,
	DE_CLONE,
	DE_FORK_DONE,
	DE_VFORK_DONE,
	DE_CLONE_DONE,
	DE_SYSCALL_ENTER,
	DE_SYSCALL_RETURN,
	DE_EXEC,
	DE_MAX,
} debugger_event;

void dump_ram_line(void* offset, size_t length);
void dump_ram(void* offset, ssize_t length, size_t linesize);

void debugger_state_init(debugger_state* state);
int debugger_set_breakpoint(debugger_state* state, pid_t pid, void* addr);
int debugger_wait_syscall(debugger_state* state, pid_t pid);
long debugger_get_syscall_number(debugger_state* state, pid_t pid);
void debugger_set_syscall_number(debugger_state * state, pid_t pid, long scnr);
long debugger_get_syscall_arg(debugger_state *d, pid_t pid, int argno);
void debugger_set_syscall_arg(debugger_state *d, pid_t pid, int argno, unsigned long nu);
int debugger_continue(debugger_state *state, pid_t pid);
int debugger_single_step(debugger_state* state, pid_t pid);
debugger_event debugger_get_events(debugger_state* state, pid_t pid, int* retval, int block);
const char* debugger_get_event_name(debugger_event de);

int attach_process(pid_t pid);
pid_t start_debuggee(char* path, char** args, char** env);
int read_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len);
int write_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len);
void* get_instruction_pointer(pid_t pid);

//RcB: DEP "debuglib.c"

#endif
