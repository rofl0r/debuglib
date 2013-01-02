#include <sys/syscall.h>
#include <stdint.h>

enum sc_type {
	TRACE_DESC          = 1 << 0,
	TRACE_FILE          = 1 << 1,
	TRACE_IPC           = 1 << 2,
	TRACE_NETWORK       = 1 << 3,
	TRACE_PROCESS       = 1 << 4,
	TRACE_SIGNAL        = 1 << 5,
	TRACE_MEMORY        = 1 << 6,
	SYSCALL_NEVER_FAILS = 1 << 7,
};

#define TD TRACE_DESC
#define TF TRACE_FILE
#define TI TRACE_IPC
#define TN TRACE_NETWORK
#define TP TRACE_PROCESS
#define TS TRACE_SIGNAL
#define TM TRACE_MEMORY
#define NF SYSCALL_NEVER_FAILS
#define MAX_ARGS 6
#define MA MAX_ARGS

#if 0
/* gcc does not align this to 16bit */
typedef struct syscalldef {
	const unsigned argcount:3;
	const unsigned nameoffset:13;
} syscalldef __attribute__((aligned(2))) __attribute__((packed));
#else
typedef uint16_t syscalldef;
#endif

#if 0
#undef __x86_64__
#define __MIPS__
#define LINUX_MIPSN32
#endif

#if !defined(__MIPS__)
#define SYSCALL_START 0
#else
#  if !defined(LINUX_MIPSN32) && !defined(LINUX_MIPSN64)
#    define SYSCALL_START 4000
#  elif defined(LINUX_MIPSN32)
#    define SYSCALL_START 6000
#  elif defined(LINUX_MIPSN64)
#    define SYSCALL_START 5000
#  else
#    error "failed to detect mips ABI variant"
#  endif
#endif

#define SYSCALL_OR_NUM(NR, SCNR) (NR - SYSCALL_START)
#define MAKE_UINT16(argcount, nameoff) ((nameoff & 0x1fff) | (argcount << 13))

#ifdef __x86_64__
#include "arch/x86_64/syscalldefs.h"
#elif defined(__i386__)
#include "arch/i386/syscalldefs.h"
#elif defined(__x32__)
#include "arch/x32/syscalldefs.h"
#elif defined(__ARM__)
#include "arch/arm/syscalldefs.h"
#elif defined(__powerpc__)
#include "arch/powerpc/syscalldefs.h"
#elif defined(__microblaze__)
#include "arch/microblaze/syscalldefs.h"
#elif defined(__MIPS__)
#include "arch/mips/syscalldefs.h"
#else
#error "failed to detect ARCH"
#endif

#include "../lib/include/macros.h"

static inline int invalid(unsigned sc) {
	return((int) sc - SYSCALL_START < 0 || sc - SYSCALL_START > ARRAY_SIZE(syscalldefs));
}

unsigned syscall_get_argcount(unsigned sc) {
	//return syscalldefs[sc].argcount;
	return invalid(sc) ? 0 : syscalldefs[sc - SYSCALL_START] >> 13;
}

const char* syscall_get_name(unsigned sc) {
	//return syscallnames + syscalldefs[sc].nameoffset;
	return invalid(sc) ? "" : syscallnames + (syscalldefs[sc - SYSCALL_START] & 0x1fff);
}

