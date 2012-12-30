#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <errno.h>
#include <signal.h>

#include "../lib/include/macros.h"
#include "../lib/include/timelib.h"
#include "../lib/include/strswitch.h"

#include "process_maps.h"
#include "debuglib.h"
#include "signals.h"

#define ARCH_I386 0
#define ARCH_AMD64 1

#ifndef ARCH
#error need to set ARCH to ARCH_I386 or ARCH_AMD64
#endif

#if (ARCH == ARCH_I386)
# define ARCH_IP EIP
# define ARCH_BP_INSTR_SIZE 1
# define ARCH_BP_INSTR "\xCC"

#elif (ARCH == ARCH_AMD64)
# define ARCH_IP RIP
# define ARCH_BP_INSTR_SIZE 1
# define ARCH_BP_INSTR "\xCC"

#else
# error this platform is not supported yet. feel free to send patches.
#endif


void debugger_state_init(debugger_state* state) {
	state->breakpoints = hashlist_new(64, sizeof(breakpointinfo));
	state->processmaps = NULL;
}

static breakpointinfo* get_bpinfo(debugger_state* state, void* addr) {
	breakpointinfo* bp = NULL;
	sblist* bucket;
	bucket = hashlist_get(state->breakpoints, (uint32_t) (size_t) addr);
	if(bucket) {
		sblist_iter(bucket, bp) {
			if(bp->addr == addr) return bp;
		}
	}
	return NULL;
}

static breakpointinfo* add_new_bpinfo(debugger_state* state, void* addr) {
	breakpointinfo new_bp = {
		.addr = addr,
		.bp_instr_size = ARCH_BP_INSTR_SIZE,
		.bp_backup = {0},
		.active = 0,
	};
	if(!hashlist_add(state->breakpoints, (uint32_t) (size_t) addr, &new_bp))
		return get_bpinfo(state, addr);
	else return NULL;
}

static void restore_breakpoint_mem(pid_t pid, breakpointinfo* bp) {
	if(write_process_memory_slow(pid, bp->addr, bp->bp_backup, bp->bp_instr_size))
		bp->active = 0;
}

static int activate_breakpoint(pid_t pid, breakpointinfo* bp) {
	if(!(read_process_memory_slow(pid, bp->bp_backup, bp->addr, bp->bp_instr_size)))
		return 0;
	if(!(write_process_memory_slow(pid, bp->addr, (void*) ARCH_BP_INSTR, bp->bp_instr_size)))
		return 0;
	bp->active = 1;
	return 1;
}

int debugger_set_breakpoint(debugger_state* state, pid_t pid, void* addr) {
	breakpointinfo* bp = get_bpinfo(state, addr);
	if(!bp) {
		bp = add_new_bpinfo(state, addr);
	} else if (bp->active) {
		printf("breakpoint %p is already active\n", addr);
		return 0;
	}
	return activate_breakpoint(pid, bp);
	/*
	map_data* dest = find_map_for_addr(processmaps, bp->addr);
	if(!dest) {
		return 0;
	}
	bp->map_perms = dest->perms;
	if((!(bp->map_perms & MDP_W)) || (!(bp->map_perms & MDP_R)) || (!(bp->map_perms & MDP_X)))
		mprotect(dest->address.start, process_map_size(dest), PROT_NONE);
	*/
}

void* get_instruction_pointer(pid_t pid) {
	long ret;
	ret = ptrace(PTRACE_PEEKUSER, pid, WORD_SIZE * ARCH_IP, NULL);
	if(errno) {
		perror("ptrace_peekuser");
		return NULL;
	}
	return (void*) ret;
}

int set_instruction_pointer(pid_t pid, void* addr) {
	long ret;
	ret = ptrace(PTRACE_POKEUSER, pid, WORD_SIZE * ARCH_IP, addr);
	if(ret == -1) {
		perror("ptrace_pokeuser");
		return 0;
	}
	return 1;
}

static int set_debug_options(pid_t pid) {
	long options = 0L
	          | PTRACE_O_TRACEEXEC
	          | PTRACE_O_TRACEEXIT
	          | PTRACE_O_TRACEFORK
	          | PTRACE_O_TRACEVFORK 
	          | PTRACE_O_TRACECLONE 
	          | PTRACE_O_TRACEVFORKDONE;
	
	if(ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1) {
		perror("ptrace_setoptions");
		return 0;
	}
	return 1;
}

int attach_process(pid_t pid) {
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		perror("ptrace attach");
		return 0;
	}
	return set_debug_options(pid);
}

pid_t start_debuggee(char* path, char** args, char** env) {
	pid_t result = fork();
	if(result == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if(execve(path, args, env) == -1) {
			perror("execve");
			goto ret_err;
		}
	} else if (result == -1) {
		perror("fork");
		ret_err:
		return (pid_t) -1;
	}
	msleep(40); // give the new process a chance to startup
	if(set_debug_options(result))
		return result;
	goto ret_err;
}

static int single_step(pid_t pid) {
	if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
		perror("ptrace_singlestep");
		return 0;
	}
	return 1;
}

int debugger_single_step(debugger_state* state, pid_t pid) {
	breakpointinfo *bp;
	void *ip = get_instruction_pointer(pid);
	int ret, reset_bp = 0;
	if(ip) {
		bp = get_bpinfo(state, ip);
		if(bp && bp->active) {
			// if we continue from a breakpoint, we have to restore its original mem contents,
			restore_breakpoint_mem(pid, bp);
			reset_bp = 1;
		}
	}
	ret = single_step(pid);
	msleep(40);
	if(reset_bp) 
		activate_breakpoint(pid, bp);
	return ret;
}

int debugger_continue(debugger_state *state, pid_t pid) {
	breakpointinfo *bp;
	void *ip = get_instruction_pointer(pid);
	void *bp_ip;
	if(ip) {
		bp_ip = (void*) ((uintptr_t) ip - ARCH_BP_INSTR_SIZE);
		bp = get_bpinfo(state, bp_ip); // ip is actually already at the next instr.
		if(bp && bp->active) {
			// if we continue from a breakpoint, we have to restore its original mem contents,
			// set the ip again to its location,
			// then we single step once and reinject the trap instruction. after that we can safely continue.
			/*restore_breakpoint_mem(pid, bp);
			set_instruction_pointer(pid, bp_ip);
			single_step(pid);
			msleep(40); //give a short delay to propagate the single step event to the child...
			activate_breakpoint(pid, bp); */
			set_instruction_pointer(pid, bp_ip);
			debugger_single_step(state, pid);
		}
	}
	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror("ptrace_cont");
		return 0;
	}
	return 1;
}

static const long alignmask = (long) WORD_SIZE - 1L;
static const long not_alignmask = ~((long) WORD_SIZE - 1L);

/* source addr points to the *other* process' mem */
int read_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len) {
	unsigned char misaligned = (uintptr_t) source_addr & alignmask;
	unsigned char* out = dest_addr;
	unsigned char* src = source_addr;
	long read_buf;
	unsigned i, chunksize;
	if(misaligned) {
		read_buf = ptrace(PTRACE_PEEKDATA, pid, (uintptr_t) source_addr & (~(alignmask)), NULL);
		if(errno) {
			peek_err:
			perror("ptrace_peekdata");
			return 0;
		}
		for(i = misaligned; len && i < WORD_SIZE; i++) {
			*(out++) = ((unsigned char*)&read_buf)[i];
			len--;
			src++;
		}
	}
	while(len) {
		read_buf = ptrace(PTRACE_PEEKDATA, pid, src, NULL);
		if(errno) goto peek_err;
		chunksize = MIN(len, WORD_SIZE);
		for(i = 0; i < chunksize; i++)
			*(out++) = ((unsigned char*)&read_buf)[i];
		src += chunksize;
		len -= chunksize;
	}
	return 1;
}



/* source addr points to the *our* process' mem */
int write_process_memory_slow(pid_t pid, void* dest_addr, void* source_addr, size_t len) {
	unsigned char misaligned = (uintptr_t) dest_addr & alignmask;
	unsigned char* base_addr;
	unsigned char* dst = dest_addr;
	unsigned char* src = source_addr;
	union {
		long l;
		unsigned char c[sizeof(long)];
	} read_buf;
	unsigned i, chunksize;
	if(misaligned) {
		base_addr = (void*) ((uintptr_t) dest_addr & not_alignmask);
		read_buf.l = ptrace(PTRACE_PEEKDATA, pid, base_addr, NULL);
		if(errno) {
			peek_err:
			perror("ptrace_peekdata");
			ret_0:
			return 0;
		}
		for(i = misaligned; len && i < WORD_SIZE; i++) {
			read_buf.c[i] = *(src++);
			len--;
		}
		if(ptrace(PTRACE_POKEDATA, pid, base_addr, read_buf.l) == -1) {
			pokemon:
			perror("ptrace_pokedata");
			goto ret_0;
		}
		dst = (unsigned char*) ((uintptr_t) base_addr + WORD_SIZE);
	}
	
	while(len) {
		chunksize = MIN(len, WORD_SIZE);
		misaligned = WORD_SIZE - chunksize;
		if(misaligned) {
			read_buf.l = ptrace(PTRACE_PEEKDATA, pid, dst, NULL);
			if(errno) goto peek_err;
		}
		for(i = 0; i < chunksize; i++) {
			read_buf.c[i] = *src++;
			len--;
		}
		if(ptrace(PTRACE_POKEDATA, pid, dst, read_buf.l) == -1) {
			goto pokemon;
		}
		dst += chunksize;
	}
	return 1;
}

static const int event_translate_tbl[] = {
	[DE_NONE] = 0,
	[DE_HIT_BP] = 0,
	[DE_EXIT] = PTRACE_EVENT_EXIT,
	[DE_FORK] = PTRACE_EVENT_FORK,
	[DE_VFORK] = PTRACE_EVENT_VFORK,
	[DE_CLONE] = PTRACE_EVENT_CLONE,
	//[DE_FORK_DONE] = PTRACE_EVENT_FORK_DONE,
	[DE_VFORK_DONE] = PTRACE_EVENT_VFORK_DONE,
	//[DE_CLONE_DONE] = PTRACE_EVENT_CLONE_DONE,
	[DE_EXEC] = PTRACE_EVENT_EXEC,
};

static int translate_event(int event) {
	unsigned i;
	for(i = 0; i < ARRAY_SIZE(event_translate_tbl); i++)
		if(event_translate_tbl[i] == event)
			return i;
	return 0;
}

debugger_event get_debugger_events(debugger_state* state, pid_t pid, int* retval) {
	debugger_event res = DE_NONE;
	unsigned long ev_data;
	siginfo_t sig_data;
	int ret = waitpid(pid, retval, WNOHANG);
	void* ip;
	breakpointinfo* bp;
	
	if(ret == -1) {
		if(errno == ECHILD) 
			res = DE_EXIT;
		//else 
			perror("waitpid");
	} else if(wait != 0) {
		if(ptrace(PTRACE_GETEVENTMSG, pid, NULL, &ev_data) == -1) {
/*			if(errno == ESRCH) 
				res = DE_EXIT;
			//else */
				perror("ptrace_geteventmsg");
			return res;
		}
		if(ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig_data) == -1) {
/*			if(errno == ESRCH) 
				res = DE_EXIT;
			//else */
				perror("ptrace_getsiginfo");
			return res;
		}
		printf("got signal %s\n", get_signal_name(sig_data.si_signo));
		
		
		switch(sig_data.si_signo) {
			case SIGTRAP:
				ip = get_instruction_pointer(pid);
				if(ip) {
					printf("instr pointer is at %p\n", ip);
					bp = get_bpinfo(state, ip);
					if(bp) {
						printf("hit breakpoint!\n");
					}
				}

				switch ((*retval & (~(SIGTRAP)) ) >> 8)  {
					case PTRACE_EVENT_EXEC:
						printf("PTRACE_EVENT_EXEC");
						break;
					case PTRACE_EVENT_EXIT:
						printf("PTRACE_EVENT_EXIT)");
						break;
					case PTRACE_EVENT_FORK:
						printf("PTRACE_EVENT_FORK)");
						break;
					case PTRACE_EVENT_VFORK:
						printf("PTRACE_EVENT_VFORK)");
						break;
					case PTRACE_EVENT_VFORK_DONE:
						printf("PTRACE_EVENT_VFORK_DONE)");
						break;
					case PTRACE_EVENT_CLONE:
						printf("PTRACE_EVENT_CLONE)");
						break;
					
					default: break;
					
				}
				if((ret = translate_event(((*retval & (~(SIGTRAP)) ) >> 8))))
					return ret;
				break;
			default:
				break;
		}
		if(ev_data != 0) printf("XXXXXXXXXXXXXXXXXXXXXX");
		printf("event info: %lu\n", ev_data);
		
		
		if(WIFEXITED(*retval)) puts("WIFEXITED");
		if(WIFSIGNALED(*retval)) puts("WIFSIGNALED");
		if(WIFSTOPPED(*retval)) puts("WIFSTOPPED");
		if(WIFCONTINUED(*retval)) puts("WIFCONTINUED");
		//if(((*retval >> 16) & 0xffff) == 
		
		res = DE_HIT_BP;
	}
	
	return res;
}

void dump_ram_line(void* offset, size_t length) {
	unsigned i;
	for (i=0; i < length; i++)
		switch(((unsigned char*) offset)[i]) {
			case STRSWITCH_PRINTABLE:
				printf("%c", ((char*) offset)[i]);
				break;
			default:
				printf(".");
		}
	printf("\n");
}

void dump_ram(void* offset, ssize_t length, size_t linesize) {
	size_t start = 0;
	while(length > 0) {
		dump_ram_line((char*)offset + start, length > linesize ? linesize : length);
		start += linesize;
		length -= linesize;
	}
}



