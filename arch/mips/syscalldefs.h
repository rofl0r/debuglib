#ifndef __MIPS__
#error "this header is only for mips"
#endif

#if !defined(LINUX_MIPSN32) && !defined(LINUX_MIPSN64)
#    include "syscalldefs_o32.h"
#elif defined(LINUX_MIPSN32)
#    include "syscalldefs_n32.h"
#elif defined(LINUX_MIPSN64)
#    include "syscalldefs_n64.h"
#else
#    error "failed to detect mips ABI variant"
#endif
