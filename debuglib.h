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
	pid_t pid;
	hashlist* breakpoints;
	sblist* processmaps;
	int syscall_ret;
} pidinfo;

typedef struct {
	sblist* pids;
} debugger_state;

typedef enum {
	DE_NONE = 0,
	DE_HIT_BP,
	DE_EXIT, /* debugger notification when a process is about to exit. exitstatus can be queried with WEXITSTATUS(retval) */
	DE_FORK,
	DE_VFORK,
	DE_CLONE,
	DE_FORK_DONE,
	DE_VFORK_DONE,
	DE_CLONE_DONE,
	DE_SYSCALL_ENTER,
	DE_SYSCALL_RETURN,
	DE_EXEC,
	DE_SIGNAL,
	DE_EXITED, /* custom notification when the process is done exiting. exitstatus is returned directly */
	DE_MAX,
} debugger_event;

void dump_ram_line(void* offset, size_t length);
void dump_ram(void* offset, size_t length, size_t linesize);

void debugger_state_init(debugger_state*);
size_t debugger_get_pidcount(debugger_state* d);
pid_t debugger_pid_from_pidindex(debugger_state* d, size_t index);
ssize_t debugger_pidindex_from_pid(debugger_state* d, pid_t pid);
void debugger_add_pid(debugger_state* d, pid_t pid);
void debugger_remove_pid(debugger_state* d, pid_t pid);
void debugger_set_pid(debugger_state *d, size_t pidindex, pid_t pid);
int debugger_set_breakpoint(debugger_state* state, size_t pidindex, void* addr);
void* debugger_get_ip(debugger_state* d, size_t pidindex);
int debugger_set_ip(debugger_state* d, size_t pidindex, void* addr);
int debugger_attach(debugger_state *d, pid_t pid);
int debugger_detach(debugger_state *d, size_t pidindex);
size_t debugger_exec(debugger_state* d, char* path, char** args, char** env);
/* tells the debugger to signal on next syscall enter/return. does not actually wait. */
int debugger_wait_syscall_pid(debugger_state* d, pid_t pid, int sig);
int debugger_wait_syscall(debugger_state* d, size_t pidindex);
long debugger_get_syscall_number(debugger_state* state, size_t pidindex);
long debugger_get_syscall_arg(debugger_state *d, size_t pidindex, int argno);
void debugger_set_syscall_arg(debugger_state *d, size_t pidindex, int argno, unsigned long nu);
void debugger_set_syscall_number(debugger_state * state, size_t pidindex, long scnr);
int debugger_single_step(debugger_state* state, size_t pidindex);
int debugger_continue(debugger_state *state, size_t pidindex);
debugger_event debugger_get_events(debugger_state* state, size_t pidindex, int* retval, int block);
const char* debugger_get_event_name(debugger_event de);

int read_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len);
int write_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len);

#pragma RcB2 DEP "debuglib.c"

#endif
