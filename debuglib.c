#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
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

#ifdef __x86_64__
#define ARCH ARCH_AMD64
#elif __i386__
#define ARCH ARCH_I386
#endif

#ifndef ARCH
#error need to set ARCH to ARCH_I386 or ARCH_AMD64
#endif

#if (ARCH == ARCH_I386)
# define ARCH_IP EIP
# define ARCH_BP_INSTR_SIZE 1
# define ARCH_BP_INSTR "\xCC"
# define ARCH_SYSCALLNR_REG orig_eax
//ebx, ecx, edx, esi, edi, ebp
# define ARCH_SYSCALL_ARG1 ebx
# define ARCH_SYSCALL_ARG2 ecx
# define ARCH_SYSCALL_ARG3 edx
# define ARCH_SYSCALL_ARG4 esi
# define ARCH_SYSCALL_ARG5 edi
# define ARCH_SYSCALL_ARG6 ebp
# define ARCH_SYSCALL_RET_REG eax

#elif (ARCH == ARCH_AMD64)
# define ARCH_IP RIP
# define ARCH_BP_INSTR_SIZE 1
# define ARCH_BP_INSTR "\xCC"
# define ARCH_SYSCALLNR_REG orig_rax
# define ARCH_SYSCALL_ARG1 rdi
# define ARCH_SYSCALL_ARG2 rsi
# define ARCH_SYSCALL_ARG3 rdx
# define ARCH_SYSCALL_ARG4 r10
# define ARCH_SYSCALL_ARG5 r8
# define ARCH_SYSCALL_ARG6 r9
# define ARCH_SYSCALL_RET_REG rax

#else
# error this platform is not supported yet. feel free to send patches.
#endif
# define ARCH_SYSCALL_ARG(NR) ARCH_SYSCALL_ARG ## NR


const char event_strings[DE_MAX][20] = {
	[DE_NONE] = "DE_NONE",
	[DE_HIT_BP] = "DE_HIT_BP",
	[DE_EXIT] = "DE_EXIT",
	[DE_FORK] = "DE_FORK",
	[DE_VFORK] = "DE_VFORK",
	[DE_CLONE] = "DE_CLONE",
	[DE_FORK_DONE] = "DE_FORK_DONE",
	[DE_VFORK_DONE] = "DE_VFORK_DONE",
	[DE_CLONE_DONE] = "DE_CLONE_DONE",
	[DE_SYSCALL_ENTER] = "DE_SYSCALL_ENTER",
	[DE_SYSCALL_RETURN] = "DE_SYSCALL_RETURN",
	[DE_EXEC] = "DE_EXEC",
	[DE_SIGNAL] = "DE_SIGNAL",
	[DE_EXITED] = "DE_EXITED",
};

const char* debugger_get_event_name(debugger_event de) {
	return event_strings[de];
}

void debugger_state_init(debugger_state* state) {
	state->pids = sblist_new(sizeof(pidinfo), 8);
}

size_t debugger_get_pidcount(debugger_state* d) {
	return sblist_getsize(d->pids);
}

pid_t debugger_pid_from_pidindex(debugger_state* d, size_t index) {
	if(index > sblist_getsize(d->pids)) return -1;
	pidinfo* ret = sblist_get(d->pids, index);
	return ret->pid;
}

static ssize_t pid_index(debugger_state* d, pid_t pid) {
	pidinfo* ret;
	sblist_iter_counter(d->pids, i, ret) {
		if(ret->pid == pid) return i;
	}
	return -1;
}

static int have_pidindex(debugger_state* d, pid_t pid) {
	return pid_index(d, pid) != -1;
}

ssize_t debugger_pidindex_from_pid(debugger_state* d, pid_t pid) {
	ssize_t res = pid_index(d, pid);
	if(res == -1) {
		dprintf(2, "error: could not find pid %d\n", pid);
		assert(0);
	}
	return res;
}

static breakpointinfo* get_bpinfo(pidinfo* state, uintptr_t addr) {
	if(!state->breakpoints) goto out;
	breakpointinfo* bp = NULL;
	sblist* bucket;
	bucket = hashlist_get(state->breakpoints, (uint32_t) addr);
	if(bucket) {
		sblist_iter(bucket, bp) {
			if(bp->addr == addr) return bp;
		}
	}
	out:
	return NULL;
}

static breakpointinfo* add_new_bpinfo(pidinfo* state, uintptr_t addr) {
	breakpointinfo new_bp = {
		.addr = addr,
		.bp_instr_size = ARCH_BP_INSTR_SIZE,
		.bp_backup = {0},
		.active = 0,
	};
	if(!state->breakpoints) state->breakpoints = hashlist_new(64, sizeof(breakpointinfo));
	if(!hashlist_add(state->breakpoints, (uint32_t) addr, &new_bp))
		return get_bpinfo(state, addr);
	return NULL;
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

static inline pidinfo* get_pidinfo(debugger_state* state, size_t pidindex) {
	return sblist_get(state->pids, pidindex);
}

int debugger_set_breakpoint(debugger_state* state, pid_t pid, uintptr_t addr) {
	ssize_t pidindex = debugger_pidindex_from_pid(state, pid);
	pidinfo *pi = get_pidinfo(state, pidindex);
	breakpointinfo* bp = get_bpinfo(pi, addr);
	if(!bp) {
		bp = add_new_bpinfo(pi, addr);
	} else if (bp->active) {
		dprintf(2, "breakpoint %p is already active\n", addr);
		return 0;
	}
	return activate_breakpoint(pi->pid, bp);
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

static uintptr_t get_instruction_pointer(pid_t pid) {
	long ret;
	errno = 0;
	ret = ptrace(PTRACE_PEEKUSER, pid, WORD_SIZE * ARCH_IP, NULL);
	if(errno) {
		perror("ptrace_peekuser");
		return 0;
	}
	return ret;
}

uintptr_t debugger_get_ip(debugger_state* d, pid_t pid) {
	ssize_t pidindex = debugger_pidindex_from_pid(d, pid);
	pidinfo *pi = get_pidinfo(d, pidindex);
	return get_instruction_pointer(pi->pid);
}

static int set_instruction_pointer(pid_t pid, uintptr_t addr) {
	long ret;
	ret = ptrace(PTRACE_POKEUSER, pid, WORD_SIZE * ARCH_IP, addr);
	if(ret == -1) {
		perror("ptrace_pokeuser");
		return 0;
	}
	return 1;
}

int debugger_set_ip(debugger_state* d, pid_t pid, uintptr_t addr) {
	return set_instruction_pointer(pid, addr);
}

static int set_debug_options(pid_t pid) {
	long options = 0L
	          | PTRACE_O_TRACEEXEC
	          | PTRACE_O_TRACEEXIT
	          | PTRACE_O_TRACEFORK
	          | PTRACE_O_TRACEVFORK
	          | PTRACE_O_TRACECLONE
	          | PTRACE_O_TRACEVFORKDONE
	          | PTRACE_O_TRACESYSGOOD
	          ;

	if(ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1) {
		perror("ptrace_setoptions");
		return 0;
	}
	return 1;
}

void debugger_add_pid(debugger_state* d, pid_t pid) {
	pidinfo pi = {0};
	pi.pid = pid;
	sblist_add(d->pids, &pi);
}

static void free_bpinfo(pidinfo *pi) {
	if(pi->breakpoints) hashlist_free(pi->breakpoints);
	pi->breakpoints = 0;
}

static void free_processmaps(pidinfo *pi) {
	if(pi->processmaps) sblist_free(pi->processmaps);
	pi->processmaps = 0;
}

void debugger_remove_pid(debugger_state* d, pid_t pid) {
	ssize_t idx = debugger_pidindex_from_pid(d, pid);
	if(idx == -1) return;
	pidinfo *pi = get_pidinfo(d, idx);
	pi->pid = -1;
	free_bpinfo(pi);
	free_processmaps(pi);
	sblist_delete(d->pids, idx);
}

void debugger_set_pid(debugger_state *d, size_t pidindex, pid_t pid) {
	pidinfo *pi = get_pidinfo(d, pidindex);
	pi->pid = pid;
}

int debugger_attach(debugger_state *d, pid_t pid) {
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		perror("ptrace attach");
		return 0;
	}
	debugger_add_pid(d, pid);
	return set_debug_options(pid);
}

int debugger_detach(debugger_state *d, pid_t pid) {
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		perror("ptrace detach");
		return 0;
	}
	debugger_remove_pid(d, pid);
	return 1;
}

pid_t debugger_exec(debugger_state* d, const char* path, char *const args[], char* const env[]) {
	pid_t result = fork();
	errno = 0;
	if(result == 0) {
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace_traceme");
		}
		if(execve(path, args, env) == -1) {
			perror("execve");
			_exit(1);
		}
	} else if (result == -1) {
		perror("fork");
		ret_err:
		return -1;
	}
	msleep(100); // give the new process a chance to startup
	if(set_debug_options(result)) {
		debugger_add_pid(d, result);
		return result;
	}
	goto ret_err;
}

int debugger_wait_syscall(debugger_state* d, pid_t pid, int sig) {
	if(ptrace(PTRACE_SYSCALL, pid, 0, sig) == -1) {
#ifdef DEBUG
		dprintf(2, "ptrace pid %d\n", (int) pid);
		perror("ptrace_syscall");
#endif
		return 0;
	}
	return 1;
}

int debugger_wait_syscall_retry(debugger_state* d, pid_t pid, int sig) {
	for(;;) {
		/* we need to sleep for a tiny amount, otherwise PTRACE_SYSCALL
		   will fail with "no such process" */
		if(!debugger_wait_syscall(d, pid, sig)) {
			if(errno != ESRCH) return 0;
			usleep(10);
		} else
			return 1;
	}
}

long debugger_get_syscall_number(debugger_state* d, pid_t pid) {
#if 0
	long ret;
	errno = 0;
	ret = ptrace(PTRACE_PEEKUSER, pid, WORD_SIZE * ARCH_SYSCALLNR_REG, NULL);
	if(errno) {
		perror(__FUNCTION__);
		ret = -1L;
	}
	return ret;
#else
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return -1;
	}
	return regs.ARCH_SYSCALLNR_REG;
#endif
}

long debugger_get_syscall_arg(debugger_state *d, pid_t pid, int argno) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return -1;
	}

	switch(argno) {
		case 1: return regs.ARCH_SYSCALL_ARG(1);
		case 2: return regs.ARCH_SYSCALL_ARG(2);
		case 3: return regs.ARCH_SYSCALL_ARG(3);
		case 4: return regs.ARCH_SYSCALL_ARG(4);
		case 5: return regs.ARCH_SYSCALL_ARG(5);
		case 6: return regs.ARCH_SYSCALL_ARG(6);
		default:
			dprintf(2, "error: invalid number of syscall args\n");
			return -1;
	}
}

void debugger_set_syscall_arg(debugger_state *d, pid_t pid, int argno, unsigned long nu) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return;
	}

	switch(argno) {
		case 1: regs.ARCH_SYSCALL_ARG(1) = nu; break;
		case 2: regs.ARCH_SYSCALL_ARG(2) = nu; break;
		case 3: regs.ARCH_SYSCALL_ARG(3) = nu; break;
		case 4: regs.ARCH_SYSCALL_ARG(4) = nu; break;
		case 5: regs.ARCH_SYSCALL_ARG(5) = nu; break;
		case 6: regs.ARCH_SYSCALL_ARG(6) = nu; break;
		default:
			dprintf(2, "error: invalid number of syscall args\n");
			return;
	}

	if(ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return;
	}
}

long debugger_get_syscall_ret(debugger_state *d, pid_t pid) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return -1;
	}

	return regs.ARCH_SYSCALL_RET_REG;
}

void debugger_set_syscall_ret(debugger_state *d, pid_t pid, unsigned long nu) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return;
	}

	regs.ARCH_SYSCALL_RET_REG = nu;

	if(ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return;
	}
}

void debugger_set_syscall_number(debugger_state * d, pid_t pid, long scnr) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
		return;
	}
	regs.ARCH_SYSCALLNR_REG = scnr;
	if(ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
		perror(__FUNCTION__);
	}
	return;
}

static int single_step(pid_t pid) {
	if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
		perror("ptrace_singlestep");
		return 0;
	}
	return 1;
}

int debugger_single_step(debugger_state* d, pid_t pid) {
	ssize_t pidindex = debugger_pidindex_from_pid(d, pid);
	pidinfo *pi = get_pidinfo(d, pidindex);
	breakpointinfo *bp;
	uintptr_t ip = get_instruction_pointer(pid);
	int ret, reset_bp = 0;
	if(ip) {
		bp = get_bpinfo(pi, ip);
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

int debugger_continue(debugger_state *d, pid_t pid) {
	size_t pidindex = debugger_pidindex_from_pid(d, pid);
	pidinfo *pi = get_pidinfo(d, pidindex);
	breakpointinfo *bp;
	uintptr_t ip = get_instruction_pointer(pid);
	uintptr_t bp_ip;
	if(ip) {
		bp_ip = ip - ARCH_BP_INSTR_SIZE;
		bp = get_bpinfo(pi, bp_ip); // ip is actually already at the next instr.
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
			debugger_single_step(d, pid);
		}
	}
	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror("ptrace_cont");
		return 0;
	}
	return 1;
}

static const debugger_event event_translate_tbl[] = {
	[PTRACE_EVENT_EXIT] = DE_EXIT,
	[PTRACE_EVENT_FORK] = DE_FORK,
	[PTRACE_EVENT_VFORK] = DE_VFORK,
	[PTRACE_EVENT_CLONE] = DE_CLONE,
	//[PTRACE_EVENT_FORK_DONE] = DE_FORK_DONE,
	[PTRACE_EVENT_VFORK_DONE] = DE_VFORK_DONE,
	// [PTRACE_EVENT_CLONE_DONE] = DE_CLONE_DONE,
	[PTRACE_EVENT_EXEC] = DE_EXEC,
};

static debugger_event translate_event(pidinfo* state, int event) {
	if(event & 0x80) {
		/* syscall return/exit, signaled from PTRACE_O_TRACESYSGOOD */
		debugger_event res;
		if(state->syscall_ret) res = DE_SYSCALL_RETURN;
		else res = DE_SYSCALL_ENTER;
		state->syscall_ret = ~state->syscall_ret;
		return res;
	}
	event >>= 8;
	switch(event) {
		case PTRACE_EVENT_EXIT:
		case PTRACE_EVENT_FORK:
		case PTRACE_EVENT_VFORK:
		case PTRACE_EVENT_CLONE:
		case PTRACE_EVENT_VFORK_DONE:
		case PTRACE_EVENT_EXEC:
			return event_translate_tbl[event];
		default:
			break;
	}
	return DE_NONE;
}

#ifndef __WALL
#define __WALL 0x40000000
#endif

debugger_event debugger_get_events(debugger_state* d, pid_t *pid, int* retval, int block) {
	debugger_event res = DE_NONE;
	unsigned long ev_data;
	siginfo_t sig_data;

	int ret = waitpid(*pid, retval, __WALL | (block ? 0 : WNOHANG));
	uintptr_t ip;
	breakpointinfo* bp;

	if(ret == 0) {
		return DE_NONE;
	} else if(ret == -1) {
		//if(errno == ECHILD)
		//	res = DE_EXIT;
		//else
			dprintf(2, "wp error ret %d, pid %d\n", ret, (int) *pid);
			perror("waitpid");
			return DE_NONE;
	} else {
		*pid = ret;
		//if(WIFEXITED(*retval)) dprintf(2, "WIFEXITED\n");
		//if(WIFSIGNALED(*retval)) dprintf(2, "WIFSIGNALED\n");
		//if(WIFSTOPPED(*retval)) dprintf(2, "WIFSTOPPED\n");
		//if(WIFCONTINUED(*retval)) dprintf(2, "WIFCONTINUED\n");

		if(ret != 0) { /* FIXME was "wait" - typo ? */
			if(ptrace(PTRACE_GETEVENTMSG, *pid, NULL, &ev_data) == -1) {
				if(WIFEXITED(*retval) && !have_pidindex(d, *pid)) {
					*retval = WEXITSTATUS(*retval);
					return DE_EXITED;
				}
				perror("ptrace_geteventmsg");
			}

			if(ptrace(PTRACE_GETSIGINFO, *pid, NULL, &sig_data) == -1) {
				perror("ptrace_getsiginfo");
				return res;
			}
			//dprintf(2, "waitpid retval %d\n", *retval);
			//dprintf(2, "got signal %s\n", get_signal_name(sig_data.si_signo));

			switch(sig_data.si_signo) {
				case SIGTRAP: {
					ssize_t pidx = debugger_pidindex_from_pid(d, *pid);
					assert(pidx != -1);
					pidinfo *pi = get_pidinfo(d, pidx);

					ip = 0;
					if(pi && pi->breakpoints)
						ip = get_instruction_pointer(*pid);
					if(ip) {
						//dprintf(2, "instr pointer is at %p\n", ip);
						/* if a bp was hit, we actually land just behind it */
						bp = get_bpinfo(pi, (uintptr_t)ip - ARCH_BP_INSTR_SIZE);
						if(bp) {
							dprintf(2, "hit breakpoint!\n");
							return DE_HIT_BP;
						}
					}

					//if((res = translate_event(state, ((*retval & (~(SIGTRAP)) ) >> 8))))
					if((res = translate_event(pi, (*retval >> 8) & (~SIGTRAP)))) {
						switch(res) {
						case DE_EXIT:
							/* consumer needs to query WEXITSTATUS() himself */
						case DE_CLONE:
						case DE_VFORK:
						case DE_FORK:
						case DE_VFORK_DONE:
						case DE_EXEC:
							*retval = ev_data;
							break;
						}
						return res;
					}
					break;
				}
				default:
					/* TODO: might be interesting to provide other values from
					   sig_data, such as the signal sender pid */
					res = DE_SIGNAL;
					*retval = sig_data.si_signo;
					return res;
			}
			if(ev_data != 0) {
				dprintf(2, "XXXXXXXXXXXXXXXXXXXXXX\n");
			}
			dprintf(2, "event info: %lu\n", ev_data);

			//if(((*retval >> 16) & 0xffff) ==

			res = DE_NONE;
		}
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

void dump_ram(void* offset, size_t length, size_t linesize) {
	size_t start = 0;
	while(length) {
		size_t togo = (length > linesize ? linesize : length);
		dump_ram_line((char*)offset + start, togo);
		start += togo;
		length -= togo;
	}
}

static const long alignmask = (long) WORD_SIZE - 1L;
static const long not_alignmask = ~((long) WORD_SIZE - 1L);

/* source addr points to the *other* process' mem */
int read_process_memory_slow(pid_t pid, void* dest_addr, uintptr_t source_addr, size_t len) {
	unsigned char misaligned = source_addr & alignmask;
	unsigned char* out = dest_addr;
	uintptr_t src = source_addr;
	long read_buf;
	unsigned i, chunksize;
	errno = 0;
	if(misaligned) {
		read_buf = ptrace(PTRACE_PEEKDATA, pid, source_addr & (~(alignmask)), NULL);
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
int write_process_memory_slow(pid_t pid, uintptr_t dest_addr, void* source_addr, size_t len) {
	unsigned char misaligned = dest_addr & alignmask;
	uintptr_t base_addr;
	uintptr_t dst = dest_addr;
	unsigned char* src = source_addr;
	union {
		long l;
		unsigned char c[sizeof(long)];
	} read_buf;
	unsigned i, chunksize;
	errno = 0;
	if(misaligned) {
		base_addr = (dest_addr & not_alignmask);
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
		dst = (base_addr + WORD_SIZE);
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


