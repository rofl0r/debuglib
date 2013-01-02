static const syscalldef syscalldefs[] = {
	[SYSCALL_OR_NUM(4000, SYS_syscall)]	 = MAKE_UINT16(6, 1),
	[SYSCALL_OR_NUM(4001, SYS_exit)]	 = MAKE_UINT16(1, 9),
	[SYSCALL_OR_NUM(4002, SYS_fork)]	 = MAKE_UINT16(0, 14),
	[SYSCALL_OR_NUM(4003, SYS_read)]	 = MAKE_UINT16(3, 19),
	[SYSCALL_OR_NUM(4004, SYS_write)]	 = MAKE_UINT16(3, 24),
	[SYSCALL_OR_NUM(4005, SYS_open)]	 = MAKE_UINT16(3, 30),
	[SYSCALL_OR_NUM(4006, SYS_close)]	 = MAKE_UINT16(1, 35),
	[SYSCALL_OR_NUM(4007, SYS_waitpid)]	 = MAKE_UINT16(3, 41),
	[SYSCALL_OR_NUM(4008, SYS_creat)]	 = MAKE_UINT16(2, 49),
	[SYSCALL_OR_NUM(4009, SYS_link)]	 = MAKE_UINT16(2, 55),
	[SYSCALL_OR_NUM(4010, SYS_unlink)]	 = MAKE_UINT16(1, 60),
	[SYSCALL_OR_NUM(4011, SYS_execve)]	 = MAKE_UINT16(3, 67),
	[SYSCALL_OR_NUM(4012, SYS_chdir)]	 = MAKE_UINT16(1, 74),
	[SYSCALL_OR_NUM(4013, SYS_time)]	 = MAKE_UINT16(1, 80),
	[SYSCALL_OR_NUM(4014, SYS_mknod)]	 = MAKE_UINT16(3, 85),
	[SYSCALL_OR_NUM(4015, SYS_chmod)]	 = MAKE_UINT16(2, 91),
	[SYSCALL_OR_NUM(4016, SYS_lchown)]	 = MAKE_UINT16(3, 97),
	[SYSCALL_OR_NUM(4017, SYS_break)]	 = MAKE_UINT16(0, 104),
	[SYSCALL_OR_NUM(4018, SYS_oldstat)]	 = MAKE_UINT16(2, 110),
	[SYSCALL_OR_NUM(4019, SYS_lseek)]	 = MAKE_UINT16(3, 118),
	[SYSCALL_OR_NUM(4020, SYS_getpid)]	 = MAKE_UINT16(0, 124),
	[SYSCALL_OR_NUM(4021, SYS_mount)]	 = MAKE_UINT16(5, 131),
	[SYSCALL_OR_NUM(4022, SYS_oldumount)]	 = MAKE_UINT16(1, 137),
	[SYSCALL_OR_NUM(4023, SYS_setuid)]	 = MAKE_UINT16(1, 147),
	[SYSCALL_OR_NUM(4024, SYS_getuid)]	 = MAKE_UINT16(0, 154),
	[SYSCALL_OR_NUM(4025, SYS_stime)]	 = MAKE_UINT16(1, 161),
	[SYSCALL_OR_NUM(4026, SYS_ptrace)]	 = MAKE_UINT16(4, 167),
	[SYSCALL_OR_NUM(4027, SYS_alarm)]	 = MAKE_UINT16(1, 174),
	[SYSCALL_OR_NUM(4028, SYS_oldfstat)]	 = MAKE_UINT16(2, 180),
	[SYSCALL_OR_NUM(4029, SYS_pause)]	 = MAKE_UINT16(0, 189),
	[SYSCALL_OR_NUM(4030, SYS_utime)]	 = MAKE_UINT16(2, 195),
	[SYSCALL_OR_NUM(4031, SYS_stty)]	 = MAKE_UINT16(0, 201),
	[SYSCALL_OR_NUM(4032, SYS_gtty)]	 = MAKE_UINT16(0, 206),
	[SYSCALL_OR_NUM(4033, SYS_access)]	 = MAKE_UINT16(2, 211),
	[SYSCALL_OR_NUM(4034, SYS_nice)]	 = MAKE_UINT16(1, 218),
	[SYSCALL_OR_NUM(4035, SYS_ftime)]	 = MAKE_UINT16(1, 223),
	[SYSCALL_OR_NUM(4036, SYS_sync)]	 = MAKE_UINT16(0, 229),
	[SYSCALL_OR_NUM(4037, SYS_kill)]	 = MAKE_UINT16(2, 234),
	[SYSCALL_OR_NUM(4038, SYS_rename)]	 = MAKE_UINT16(2, 239),
	[SYSCALL_OR_NUM(4039, SYS_mkdir)]	 = MAKE_UINT16(2, 246),
	[SYSCALL_OR_NUM(4040, SYS_rmdir)]	 = MAKE_UINT16(1, 252),
	[SYSCALL_OR_NUM(4041, SYS_dup)]	 = MAKE_UINT16(1, 258),
	[SYSCALL_OR_NUM(4042, SYS_pipe)]	 = MAKE_UINT16(1, 262),
	[SYSCALL_OR_NUM(4043, SYS_times)]	 = MAKE_UINT16(1, 267),
	[SYSCALL_OR_NUM(4044, SYS_prof)]	 = MAKE_UINT16(0, 273),
	[SYSCALL_OR_NUM(4045, SYS_brk)]	 = MAKE_UINT16(1, 278),
	[SYSCALL_OR_NUM(4046, SYS_setgid)]	 = MAKE_UINT16(1, 282),
	[SYSCALL_OR_NUM(4047, SYS_getgid)]	 = MAKE_UINT16(0, 289),
	[SYSCALL_OR_NUM(4048, SYS_signal)]	 = MAKE_UINT16(1, 296),
	[SYSCALL_OR_NUM(4049, SYS_geteuid)]	 = MAKE_UINT16(0, 303),
	[SYSCALL_OR_NUM(4050, SYS_getegid)]	 = MAKE_UINT16(0, 311),
	[SYSCALL_OR_NUM(4051, SYS_acct)]	 = MAKE_UINT16(1, 319),
	[SYSCALL_OR_NUM(4052, SYS_umount)]	 = MAKE_UINT16(2, 324),
	[SYSCALL_OR_NUM(4053, SYS_lock)]	 = MAKE_UINT16(0, 331),
	[SYSCALL_OR_NUM(4054, SYS_ioctl)]	 = MAKE_UINT16(3, 336),
	[SYSCALL_OR_NUM(4055, SYS_fcntl)]	 = MAKE_UINT16(3, 342),
	[SYSCALL_OR_NUM(4056, SYS_mpx)]	 = MAKE_UINT16(0, 348),
	[SYSCALL_OR_NUM(4057, SYS_setpgid)]	 = MAKE_UINT16(2, 352),
	[SYSCALL_OR_NUM(4058, SYS_ulimit)]	 = MAKE_UINT16(0, 360),
	[SYSCALL_OR_NUM(4059, SYS_oldolduname)]	 = MAKE_UINT16(1, 367),
	[SYSCALL_OR_NUM(4060, SYS_umask)]	 = MAKE_UINT16(1, 379),
	[SYSCALL_OR_NUM(4061, SYS_chroot)]	 = MAKE_UINT16(1, 385),
	[SYSCALL_OR_NUM(4062, SYS_ustat)]	 = MAKE_UINT16(2, 392),
	[SYSCALL_OR_NUM(4063, SYS_dup2)]	 = MAKE_UINT16(2, 398),
	[SYSCALL_OR_NUM(4064, SYS_getppid)]	 = MAKE_UINT16(0, 403),
	[SYSCALL_OR_NUM(4065, SYS_getpgrp)]	 = MAKE_UINT16(0, 411),
	[SYSCALL_OR_NUM(4066, SYS_setsid)]	 = MAKE_UINT16(0, 419),
	[SYSCALL_OR_NUM(4067, SYS_sigaction)]	 = MAKE_UINT16(3, 426),
	[SYSCALL_OR_NUM(4068, SYS_sgetmask)]	 = MAKE_UINT16(0, 436),
	[SYSCALL_OR_NUM(4069, SYS_ssetmask)]	 = MAKE_UINT16(1, 445),
	[SYSCALL_OR_NUM(4070, SYS_setreuid)]	 = MAKE_UINT16(2, 454),
	[SYSCALL_OR_NUM(4071, SYS_setregid)]	 = MAKE_UINT16(2, 463),
	[SYSCALL_OR_NUM(4072, SYS_sigsuspend)]	 = MAKE_UINT16(3, 472),
	[SYSCALL_OR_NUM(4073, SYS_sigpending)]	 = MAKE_UINT16(1, 483),
	[SYSCALL_OR_NUM(4074, SYS_sethostname)]	 = MAKE_UINT16(2, 494),
	[SYSCALL_OR_NUM(4075, SYS_setrlimit)]	 = MAKE_UINT16(2, 506),
	[SYSCALL_OR_NUM(4076, SYS_getrlimit)]	 = MAKE_UINT16(2, 516),
	[SYSCALL_OR_NUM(4077, SYS_getrusage)]	 = MAKE_UINT16(2, 526),
	[SYSCALL_OR_NUM(4078, SYS_gettimeofday)]	 = MAKE_UINT16(2, 536),
	[SYSCALL_OR_NUM(4079, SYS_settimeofday)]	 = MAKE_UINT16(2, 549),
	[SYSCALL_OR_NUM(4080, SYS_getgroups)]	 = MAKE_UINT16(2, 562),
	[SYSCALL_OR_NUM(4081, SYS_setgroups)]	 = MAKE_UINT16(2, 572),
	[SYSCALL_OR_NUM(4082, SYS_reserved82)]	 = MAKE_UINT16(0, 582),
	[SYSCALL_OR_NUM(4083, SYS_symlink)]	 = MAKE_UINT16(2, 593),
	[SYSCALL_OR_NUM(4084, SYS_oldlstat)]	 = MAKE_UINT16(2, 601),
	[SYSCALL_OR_NUM(4085, SYS_readlink)]	 = MAKE_UINT16(3, 610),
	[SYSCALL_OR_NUM(4086, SYS_uselib)]	 = MAKE_UINT16(1, 619),
	[SYSCALL_OR_NUM(4087, SYS_swapon)]	 = MAKE_UINT16(2, 626),
	[SYSCALL_OR_NUM(4088, SYS_reboot)]	 = MAKE_UINT16(4, 633),
	[SYSCALL_OR_NUM(4089, SYS_readdir)]	 = MAKE_UINT16(3, 640),
	[SYSCALL_OR_NUM(4090, SYS_old_mmap)]	 = MAKE_UINT16(6, 648),
	[SYSCALL_OR_NUM(4091, SYS_munmap)]	 = MAKE_UINT16(2, 657),
	[SYSCALL_OR_NUM(4092, SYS_truncate)]	 = MAKE_UINT16(2, 664),
	[SYSCALL_OR_NUM(4093, SYS_ftruncate)]	 = MAKE_UINT16(2, 673),
	[SYSCALL_OR_NUM(4094, SYS_fchmod)]	 = MAKE_UINT16(2, 683),
	[SYSCALL_OR_NUM(4095, SYS_fchown)]	 = MAKE_UINT16(3, 690),
	[SYSCALL_OR_NUM(4096, SYS_getpriority)]	 = MAKE_UINT16(2, 697),
	[SYSCALL_OR_NUM(4097, SYS_setpriority)]	 = MAKE_UINT16(3, 709),
	[SYSCALL_OR_NUM(4098, SYS_profil)]	 = MAKE_UINT16(0, 721),
	[SYSCALL_OR_NUM(4099, SYS_statfs)]	 = MAKE_UINT16(3, 728),
	[SYSCALL_OR_NUM(4100, SYS_fstatfs)]	 = MAKE_UINT16(3, 735),
	[SYSCALL_OR_NUM(4101, SYS_ioperm)]	 = MAKE_UINT16(0, 743),
	[SYSCALL_OR_NUM(4102, SYS_socketcall)]	 = MAKE_UINT16(2, 750),
	[SYSCALL_OR_NUM(4103, SYS_syslog)]	 = MAKE_UINT16(3, 761),
	[SYSCALL_OR_NUM(4104, SYS_setitimer)]	 = MAKE_UINT16(3, 768),
	[SYSCALL_OR_NUM(4105, SYS_getitimer)]	 = MAKE_UINT16(2, 778),
	[SYSCALL_OR_NUM(4106, SYS_stat)]	 = MAKE_UINT16(2, 788),
	[SYSCALL_OR_NUM(4107, SYS_lstat)]	 = MAKE_UINT16(2, 793),
	[SYSCALL_OR_NUM(4108, SYS_fstat)]	 = MAKE_UINT16(2, 799),
	[SYSCALL_OR_NUM(4109, SYS_olduname)]	 = MAKE_UINT16(1, 805),
	[SYSCALL_OR_NUM(4110, SYS_iopl)]	 = MAKE_UINT16(0, 814),
	[SYSCALL_OR_NUM(4111, SYS_vhangup)]	 = MAKE_UINT16(0, 819),
	[SYSCALL_OR_NUM(4112, SYS_idle)]	 = MAKE_UINT16(0, 827),
	[SYSCALL_OR_NUM(4113, SYS_vm86)]	 = MAKE_UINT16(5, 832),
	[SYSCALL_OR_NUM(4114, SYS_wait4)]	 = MAKE_UINT16(4, 837),
	[SYSCALL_OR_NUM(4115, SYS_swapoff)]	 = MAKE_UINT16(1, 843),
	[SYSCALL_OR_NUM(4116, SYS_sysinfo)]	 = MAKE_UINT16(1, 851),
	[SYSCALL_OR_NUM(4117, SYS_ipc)]	 = MAKE_UINT16(6, 859),
	[SYSCALL_OR_NUM(4118, SYS_fsync)]	 = MAKE_UINT16(1, 863),
	[SYSCALL_OR_NUM(4119, SYS_sigreturn)]	 = MAKE_UINT16(0, 869),
	[SYSCALL_OR_NUM(4120, SYS_clone)]	 = MAKE_UINT16(5, 879),
	[SYSCALL_OR_NUM(4121, SYS_setdomainname)]	 = MAKE_UINT16(2, 885),
	[SYSCALL_OR_NUM(4122, SYS_uname)]	 = MAKE_UINT16(1, 899),
	[SYSCALL_OR_NUM(4123, SYS_modify_ldt)]	 = MAKE_UINT16(0, 905),
	[SYSCALL_OR_NUM(4124, SYS_adjtimex)]	 = MAKE_UINT16(1, 916),
	[SYSCALL_OR_NUM(4125, SYS_mprotect)]	 = MAKE_UINT16(3, 925),
	[SYSCALL_OR_NUM(4126, SYS_sigprocmask)]	 = MAKE_UINT16(3, 934),
	[SYSCALL_OR_NUM(4127, SYS_create_module)]	 = MAKE_UINT16(2, 946),
	[SYSCALL_OR_NUM(4128, SYS_init_module)]	 = MAKE_UINT16(3, 960),
	[SYSCALL_OR_NUM(4129, SYS_delete_module)]	 = MAKE_UINT16(2, 972),
	[SYSCALL_OR_NUM(4130, SYS_get_kernel_syms)]	 = MAKE_UINT16(1, 986),
	[SYSCALL_OR_NUM(4131, SYS_quotactl)]	 = MAKE_UINT16(4, 1002),
	[SYSCALL_OR_NUM(4132, SYS_getpgid)]	 = MAKE_UINT16(1, 1011),
	[SYSCALL_OR_NUM(4133, SYS_fchdir)]	 = MAKE_UINT16(1, 1019),
	[SYSCALL_OR_NUM(4134, SYS_bdflush)]	 = MAKE_UINT16(2, 1026),
	[SYSCALL_OR_NUM(4135, SYS_sysfs)]	 = MAKE_UINT16(3, 1034),
	[SYSCALL_OR_NUM(4136, SYS_personality)]	 = MAKE_UINT16(1, 1040),
	[SYSCALL_OR_NUM(4137, SYS_afs_syscall)]	 = MAKE_UINT16(0, 1052),
	[SYSCALL_OR_NUM(4138, SYS_setfsuid)]	 = MAKE_UINT16(1, 1064),
	[SYSCALL_OR_NUM(4139, SYS_setfsgid)]	 = MAKE_UINT16(1, 1073),
	[SYSCALL_OR_NUM(4140, SYS__llseek)]	 = MAKE_UINT16(5, 1082),
	[SYSCALL_OR_NUM(4141, SYS_getdents)]	 = MAKE_UINT16(3, 1090),
	[SYSCALL_OR_NUM(4142, SYS__newselect)]	 = MAKE_UINT16(5, 1099),
	[SYSCALL_OR_NUM(4143, SYS_flock)]	 = MAKE_UINT16(2, 1110),
	[SYSCALL_OR_NUM(4144, SYS_msync)]	 = MAKE_UINT16(3, 1116),
	[SYSCALL_OR_NUM(4145, SYS_readv)]	 = MAKE_UINT16(3, 1122),
	[SYSCALL_OR_NUM(4146, SYS_writev)]	 = MAKE_UINT16(3, 1128),
	[SYSCALL_OR_NUM(4147, SYS_cacheflush)]	 = MAKE_UINT16(3, 1135),
	[SYSCALL_OR_NUM(4148, SYS_cachectl)]	 = MAKE_UINT16(3, 1146),
	[SYSCALL_OR_NUM(4149, SYS_sysmips)]	 = MAKE_UINT16(4, 1155),
	[SYSCALL_OR_NUM(4150, SYS_setup)]	 = MAKE_UINT16(0, 1163),
	[SYSCALL_OR_NUM(4151, SYS_getsid)]	 = MAKE_UINT16(1, 1169),
	[SYSCALL_OR_NUM(4152, SYS_fdatasync)]	 = MAKE_UINT16(1, 1176),
	[SYSCALL_OR_NUM(4153, SYS__sysctl)]	 = MAKE_UINT16(1, 1186),
	[SYSCALL_OR_NUM(4154, SYS_mlock)]	 = MAKE_UINT16(2, 1194),
	[SYSCALL_OR_NUM(4155, SYS_munlock)]	 = MAKE_UINT16(2, 1200),
	[SYSCALL_OR_NUM(4156, SYS_mlockall)]	 = MAKE_UINT16(1, 1208),
	[SYSCALL_OR_NUM(4157, SYS_munlockall)]	 = MAKE_UINT16(0, 1217),
	[SYSCALL_OR_NUM(4158, SYS_sched_setparam)]	 = MAKE_UINT16(2, 1228),
	[SYSCALL_OR_NUM(4159, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1243),
	[SYSCALL_OR_NUM(4160, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1258),
	[SYSCALL_OR_NUM(4161, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1277),
	[SYSCALL_OR_NUM(4162, SYS_sched_yield)]	 = MAKE_UINT16(0, 1296),
	[SYSCALL_OR_NUM(4163, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1308),
	[SYSCALL_OR_NUM(4164, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1331),
	[SYSCALL_OR_NUM(4165, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1354),
	[SYSCALL_OR_NUM(4166, SYS_nanosleep)]	 = MAKE_UINT16(2, 1376),
	[SYSCALL_OR_NUM(4167, SYS_mremap)]	 = MAKE_UINT16(5, 1386),
	[SYSCALL_OR_NUM(4168, SYS_accept)]	 = MAKE_UINT16(3, 1393),
	[SYSCALL_OR_NUM(4169, SYS_bind)]	 = MAKE_UINT16(3, 1400),
	[SYSCALL_OR_NUM(4170, SYS_connect)]	 = MAKE_UINT16(3, 1405),
	[SYSCALL_OR_NUM(4171, SYS_getpeername)]	 = MAKE_UINT16(3, 1413),
	[SYSCALL_OR_NUM(4172, SYS_getsockname)]	 = MAKE_UINT16(3, 1425),
	[SYSCALL_OR_NUM(4173, SYS_getsockopt)]	 = MAKE_UINT16(5, 1437),
	[SYSCALL_OR_NUM(4174, SYS_listen)]	 = MAKE_UINT16(2, 1448),
	[SYSCALL_OR_NUM(4175, SYS_recv)]	 = MAKE_UINT16(4, 1455),
	[SYSCALL_OR_NUM(4176, SYS_recvfrom)]	 = MAKE_UINT16(6, 1460),
	[SYSCALL_OR_NUM(4177, SYS_recvmsg)]	 = MAKE_UINT16(3, 1469),
	[SYSCALL_OR_NUM(4178, SYS_send)]	 = MAKE_UINT16(4, 1477),
	[SYSCALL_OR_NUM(4179, SYS_sendmsg)]	 = MAKE_UINT16(3, 1482),
	[SYSCALL_OR_NUM(4180, SYS_sendto)]	 = MAKE_UINT16(6, 1490),
	[SYSCALL_OR_NUM(4181, SYS_setsockopt)]	 = MAKE_UINT16(5, 1497),
	[SYSCALL_OR_NUM(4182, SYS_shutdown)]	 = MAKE_UINT16(2, 1508),
	[SYSCALL_OR_NUM(4183, SYS_socket)]	 = MAKE_UINT16(3, 1517),
	[SYSCALL_OR_NUM(4184, SYS_socketpair)]	 = MAKE_UINT16(4, 1524),
	[SYSCALL_OR_NUM(4185, SYS_setresuid)]	 = MAKE_UINT16(3, 1535),
	[SYSCALL_OR_NUM(4186, SYS_getresuid)]	 = MAKE_UINT16(3, 1545),
	[SYSCALL_OR_NUM(4187, SYS_query_module)]	 = MAKE_UINT16(5, 1555),
	[SYSCALL_OR_NUM(4188, SYS_poll)]	 = MAKE_UINT16(3, 1568),
	[SYSCALL_OR_NUM(4189, SYS_nfsservctl)]	 = MAKE_UINT16(3, 1573),
	[SYSCALL_OR_NUM(4190, SYS_setresgid)]	 = MAKE_UINT16(3, 1584),
	[SYSCALL_OR_NUM(4191, SYS_getresgid)]	 = MAKE_UINT16(3, 1594),
	[SYSCALL_OR_NUM(4192, SYS_prctl)]	 = MAKE_UINT16(5, 1604),
	[SYSCALL_OR_NUM(4193, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 1610),
	[SYSCALL_OR_NUM(4194, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 1623),
	[SYSCALL_OR_NUM(4195, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 1636),
	[SYSCALL_OR_NUM(4196, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 1651),
	[SYSCALL_OR_NUM(4197, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 1665),
	[SYSCALL_OR_NUM(4198, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 1681),
	[SYSCALL_OR_NUM(4199, SYS_rt_sigsuspend)]	 = MAKE_UINT16(2, 1697),
	[SYSCALL_OR_NUM(4200, SYS_pread)]	 = MAKE_UINT16(6, 1711),
	[SYSCALL_OR_NUM(4201, SYS_pwrite)]	 = MAKE_UINT16(6, 1717),
	[SYSCALL_OR_NUM(4202, SYS_chown)]	 = MAKE_UINT16(3, 1724),
	[SYSCALL_OR_NUM(4203, SYS_getcwd)]	 = MAKE_UINT16(2, 1730),
	[SYSCALL_OR_NUM(4204, SYS_capget)]	 = MAKE_UINT16(2, 1737),
	[SYSCALL_OR_NUM(4205, SYS_capset)]	 = MAKE_UINT16(2, 1744),
	[SYSCALL_OR_NUM(4206, SYS_sigaltstatck)]	 = MAKE_UINT16(2, 1751),
	[SYSCALL_OR_NUM(4207, SYS_sendfile)]	 = MAKE_UINT16(4, 1764),
	[SYSCALL_OR_NUM(4210, SYS_mmap)]	 = MAKE_UINT16(6, 1773),
	[SYSCALL_OR_NUM(4211, SYS_truncate64)]	 = MAKE_UINT16(4, 1778),
	[SYSCALL_OR_NUM(4212, SYS_ftruncate64)]	 = MAKE_UINT16(4, 1789),
	[SYSCALL_OR_NUM(4213, SYS_stat64)]	 = MAKE_UINT16(2, 1801),
	[SYSCALL_OR_NUM(4214, SYS_lstat64)]	 = MAKE_UINT16(2, 1808),
	[SYSCALL_OR_NUM(4215, SYS_fstat64)]	 = MAKE_UINT16(2, 1816),
	[SYSCALL_OR_NUM(4216, SYS_pivot_root)]	 = MAKE_UINT16(2, 1824),
	[SYSCALL_OR_NUM(4217, SYS_mincore)]	 = MAKE_UINT16(3, 1835),
	[SYSCALL_OR_NUM(4218, SYS_madvise)]	 = MAKE_UINT16(3, 1843),
	[SYSCALL_OR_NUM(4219, SYS_getdents64)]	 = MAKE_UINT16(3, 1851),
	[SYSCALL_OR_NUM(4220, SYS_fcntl64)]	 = MAKE_UINT16(3, 1862),
	[SYSCALL_OR_NUM(4222, SYS_gettid)]	 = MAKE_UINT16(0, 1870),
	[SYSCALL_OR_NUM(4223, SYS_readahead)]	 = MAKE_UINT16(5, 1877),
	[SYSCALL_OR_NUM(4224, SYS_setxattr)]	 = MAKE_UINT16(5, 1887),
	[SYSCALL_OR_NUM(4225, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1896),
	[SYSCALL_OR_NUM(4226, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1906),
	[SYSCALL_OR_NUM(4227, SYS_getxattr)]	 = MAKE_UINT16(4, 1916),
	[SYSCALL_OR_NUM(4228, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1925),
	[SYSCALL_OR_NUM(4229, SYS_fgetxattr)]	 = MAKE_UINT16(4, 1935),
	[SYSCALL_OR_NUM(4230, SYS_listxattr)]	 = MAKE_UINT16(3, 1945),
	[SYSCALL_OR_NUM(4231, SYS_llistxattr)]	 = MAKE_UINT16(3, 1955),
	[SYSCALL_OR_NUM(4232, SYS_flistxattr)]	 = MAKE_UINT16(3, 1966),
	[SYSCALL_OR_NUM(4233, SYS_removexattr)]	 = MAKE_UINT16(2, 1977),
	[SYSCALL_OR_NUM(4234, SYS_lremovexattr)]	 = MAKE_UINT16(2, 1989),
	[SYSCALL_OR_NUM(4235, SYS_fremovexattr)]	 = MAKE_UINT16(2, 2002),
	[SYSCALL_OR_NUM(4236, SYS_tkill)]	 = MAKE_UINT16(2, 2015),
	[SYSCALL_OR_NUM(4237, SYS_sendfile64)]	 = MAKE_UINT16(4, 2021),
	[SYSCALL_OR_NUM(4238, SYS_futex)]	 = MAKE_UINT16(6, 2032),
	[SYSCALL_OR_NUM(4239, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 2038),
	[SYSCALL_OR_NUM(4240, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 2056),
	[SYSCALL_OR_NUM(4241, SYS_io_setup)]	 = MAKE_UINT16(2, 2074),
	[SYSCALL_OR_NUM(4242, SYS_io_destroy)]	 = MAKE_UINT16(1, 2083),
	[SYSCALL_OR_NUM(4243, SYS_io_getevents)]	 = MAKE_UINT16(5, 2094),
	[SYSCALL_OR_NUM(4244, SYS_io_submit)]	 = MAKE_UINT16(3, 2107),
	[SYSCALL_OR_NUM(4245, SYS_io_cancel)]	 = MAKE_UINT16(3, 2117),
	[SYSCALL_OR_NUM(4246, SYS_exit_group)]	 = MAKE_UINT16(1, 2127),
	[SYSCALL_OR_NUM(4247, SYS_lookup_dcookie)]	 = MAKE_UINT16(4, 2138),
	[SYSCALL_OR_NUM(4248, SYS_epoll_create)]	 = MAKE_UINT16(1, 2153),
	[SYSCALL_OR_NUM(4249, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 2166),
	[SYSCALL_OR_NUM(4250, SYS_epoll_wait)]	 = MAKE_UINT16(4, 2176),
	[SYSCALL_OR_NUM(4251, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 2187),
	[SYSCALL_OR_NUM(4252, SYS_set_tid_address)]	 = MAKE_UINT16(1, 2204),
	[SYSCALL_OR_NUM(4253, SYS_restart_syscall)]	 = MAKE_UINT16(0, 2220),
	[SYSCALL_OR_NUM(4254, SYS_fadvise64_64)]	 = MAKE_UINT16(6, 2236),
	[SYSCALL_OR_NUM(4255, SYS_statfs64)]	 = MAKE_UINT16(3, 2249),
	[SYSCALL_OR_NUM(4256, SYS_fstatfs64)]	 = MAKE_UINT16(2, 2258),
	[SYSCALL_OR_NUM(4257, SYS_timer_create)]	 = MAKE_UINT16(3, 2268),
	[SYSCALL_OR_NUM(4258, SYS_timer_settime)]	 = MAKE_UINT16(4, 2281),
	[SYSCALL_OR_NUM(4259, SYS_timer_gettime)]	 = MAKE_UINT16(2, 2295),
	[SYSCALL_OR_NUM(4260, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2309),
	[SYSCALL_OR_NUM(4261, SYS_timer_delete)]	 = MAKE_UINT16(1, 2326),
	[SYSCALL_OR_NUM(4262, SYS_clock_settime)]	 = MAKE_UINT16(2, 2339),
	[SYSCALL_OR_NUM(4263, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2353),
	[SYSCALL_OR_NUM(4264, SYS_clock_getres)]	 = MAKE_UINT16(2, 2367),
	[SYSCALL_OR_NUM(4265, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2380),
	[SYSCALL_OR_NUM(4266, SYS_tgkill)]	 = MAKE_UINT16(3, 2396),
	[SYSCALL_OR_NUM(4267, SYS_utimes)]	 = MAKE_UINT16(2, 2403),
	[SYSCALL_OR_NUM(4268, SYS_mbind)]	 = MAKE_UINT16(4, 2410),
	[SYSCALL_OR_NUM(4271, SYS_mq_open)]	 = MAKE_UINT16(4, 2416),
	[SYSCALL_OR_NUM(4272, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2424),
	[SYSCALL_OR_NUM(4273, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2434),
	[SYSCALL_OR_NUM(4274, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2447),
	[SYSCALL_OR_NUM(4275, SYS_mq_notify)]	 = MAKE_UINT16(2, 2463),
	[SYSCALL_OR_NUM(4276, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2473),
	[SYSCALL_OR_NUM(4278, SYS_waitid)]	 = MAKE_UINT16(5, 2487),
	[SYSCALL_OR_NUM(4280, SYS_add_key)]	 = MAKE_UINT16(5, 2494),
	[SYSCALL_OR_NUM(4281, SYS_request_key)]	 = MAKE_UINT16(4, 2502),
	[SYSCALL_OR_NUM(4282, SYS_keyctl)]	 = MAKE_UINT16(5, 2514),
	[SYSCALL_OR_NUM(4283, SYS_set_thread_area)]	 = MAKE_UINT16(1, 2521),
	[SYSCALL_OR_NUM(4284, SYS_inotify_init)]	 = MAKE_UINT16(0, 2537),
	[SYSCALL_OR_NUM(4285, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2550),
	[SYSCALL_OR_NUM(4286, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2568),
	[SYSCALL_OR_NUM(4287, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2585),
	[SYSCALL_OR_NUM(4288, SYS_openat)]	 = MAKE_UINT16(4, 2599),
	[SYSCALL_OR_NUM(4289, SYS_mkdirat)]	 = MAKE_UINT16(3, 2606),
	[SYSCALL_OR_NUM(4290, SYS_mknodat)]	 = MAKE_UINT16(4, 2614),
	[SYSCALL_OR_NUM(4291, SYS_fchownat)]	 = MAKE_UINT16(5, 2622),
	[SYSCALL_OR_NUM(4292, SYS_futimesat)]	 = MAKE_UINT16(3, 2631),
	[SYSCALL_OR_NUM(4293, SYS_newfstatat)]	 = MAKE_UINT16(4, 2641),
	[SYSCALL_OR_NUM(4294, SYS_unlinkat)]	 = MAKE_UINT16(3, 2652),
	[SYSCALL_OR_NUM(4295, SYS_renameat)]	 = MAKE_UINT16(4, 2661),
	[SYSCALL_OR_NUM(4296, SYS_linkat)]	 = MAKE_UINT16(5, 2670),
	[SYSCALL_OR_NUM(4297, SYS_symlinkat)]	 = MAKE_UINT16(3, 2677),
	[SYSCALL_OR_NUM(4298, SYS_readlinkat)]	 = MAKE_UINT16(4, 2687),
	[SYSCALL_OR_NUM(4299, SYS_fchmodat)]	 = MAKE_UINT16(3, 2698),
	[SYSCALL_OR_NUM(4300, SYS_faccessat)]	 = MAKE_UINT16(3, 2707),
	[SYSCALL_OR_NUM(4301, SYS_pselect6)]	 = MAKE_UINT16(6, 2717),
	[SYSCALL_OR_NUM(4302, SYS_ppoll)]	 = MAKE_UINT16(5, 2726),
	[SYSCALL_OR_NUM(4303, SYS_unshare)]	 = MAKE_UINT16(1, 2732),
	[SYSCALL_OR_NUM(4304, SYS_splice)]	 = MAKE_UINT16(6, 2740),
	[SYSCALL_OR_NUM(4305, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2747),
	[SYSCALL_OR_NUM(4306, SYS_tee)]	 = MAKE_UINT16(4, 2763),
	[SYSCALL_OR_NUM(4307, SYS_vmsplice)]	 = MAKE_UINT16(4, 2767),
	[SYSCALL_OR_NUM(4308, SYS_move_pages)]	 = MAKE_UINT16(6, 2776),
	[SYSCALL_OR_NUM(4309, SYS_set_robust_list)]	 = MAKE_UINT16(2, 2787),
	[SYSCALL_OR_NUM(4310, SYS_get_robust_list)]	 = MAKE_UINT16(3, 2803),
	[SYSCALL_OR_NUM(4311, SYS_kexec_load)]	 = MAKE_UINT16(4, 2819),
	[SYSCALL_OR_NUM(4312, SYS_getcpu)]	 = MAKE_UINT16(3, 2830),
	[SYSCALL_OR_NUM(4313, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2837),
	[SYSCALL_OR_NUM(4314, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2849),
	[SYSCALL_OR_NUM(4315, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2860),
	[SYSCALL_OR_NUM(4316, SYS_utimensat)]	 = MAKE_UINT16(4, 2871),
	[SYSCALL_OR_NUM(4317, SYS_signalfd)]	 = MAKE_UINT16(3, 2881),
	[SYSCALL_OR_NUM(4318, SYS_timerfd)]	 = MAKE_UINT16(4, 2890),
	[SYSCALL_OR_NUM(4319, SYS_eventfd)]	 = MAKE_UINT16(1, 2898),
	[SYSCALL_OR_NUM(4320, SYS_fallocate)]	 = MAKE_UINT16(6, 2906),
	[SYSCALL_OR_NUM(4321, SYS_timerfd_create)]	 = MAKE_UINT16(2, 2916),
	[SYSCALL_OR_NUM(4322, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 2931),
	[SYSCALL_OR_NUM(4323, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 2947),
	[SYSCALL_OR_NUM(4324, SYS_signalfd4)]	 = MAKE_UINT16(4, 2963),
	[SYSCALL_OR_NUM(4325, SYS_eventfd2)]	 = MAKE_UINT16(2, 2973),
	[SYSCALL_OR_NUM(4326, SYS_epoll_create1)]	 = MAKE_UINT16(1, 2982),
	[SYSCALL_OR_NUM(4327, SYS_dup3)]	 = MAKE_UINT16(3, 2996),
	[SYSCALL_OR_NUM(4328, SYS_pipe2)]	 = MAKE_UINT16(2, 3001),
	[SYSCALL_OR_NUM(4329, SYS_inotify_init1)]	 = MAKE_UINT16(1, 3007),
	[SYSCALL_OR_NUM(4330, SYS_preadv)]	 = MAKE_UINT16(6, 3021),
	[SYSCALL_OR_NUM(4331, SYS_pwritev)]	 = MAKE_UINT16(6, 3028),
	[SYSCALL_OR_NUM(4332, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 3036),
	[SYSCALL_OR_NUM(4333, SYS_perf_event_open)]	 = MAKE_UINT16(5, 3054),
	[SYSCALL_OR_NUM(4334, SYS_accept4)]	 = MAKE_UINT16(4, 3070),
	[SYSCALL_OR_NUM(4335, SYS_recvmmsg)]	 = MAKE_UINT16(5, 3078),
	[SYSCALL_OR_NUM(4336, SYS_fanotify_init)]	 = MAKE_UINT16(2, 3087),
	[SYSCALL_OR_NUM(4337, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 3101),
	[SYSCALL_OR_NUM(4338, SYS_prlimit64)]	 = MAKE_UINT16(4, 3115),
	[SYSCALL_OR_NUM(4339, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 3125),
	[SYSCALL_OR_NUM(4340, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 3143),
	[SYSCALL_OR_NUM(4341, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 3161),
	[SYSCALL_OR_NUM(4342, SYS_syncfs)]	 = MAKE_UINT16(1, 3175),
	[SYSCALL_OR_NUM(4343, SYS_sendmmsg)]	 = MAKE_UINT16(4, 3182),
	[SYSCALL_OR_NUM(4344, SYS_setns)]	 = MAKE_UINT16(2, 3191),
	[SYSCALL_OR_NUM(4345, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 3197),
	[SYSCALL_OR_NUM(4346, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 3214),
};

static const char syscallnames[] = "\0"
"syscall\0"
"exit\0"
"fork\0"
"read\0"
"write\0"
"open\0"
"close\0"
"waitpid\0"
"creat\0"
"link\0"
"unlink\0"
"execve\0"
"chdir\0"
"time\0"
"mknod\0"
"chmod\0"
"lchown\0"
"break\0"
"oldstat\0"
"lseek\0"
"getpid\0"
"mount\0"
"oldumount\0"
"setuid\0"
"getuid\0"
"stime\0"
"ptrace\0"
"alarm\0"
"oldfstat\0"
"pause\0"
"utime\0"
"stty\0"
"gtty\0"
"access\0"
"nice\0"
"ftime\0"
"sync\0"
"kill\0"
"rename\0"
"mkdir\0"
"rmdir\0"
"dup\0"
"pipe\0"
"times\0"
"prof\0"
"brk\0"
"setgid\0"
"getgid\0"
"signal\0"
"geteuid\0"
"getegid\0"
"acct\0"
"umount\0"
"lock\0"
"ioctl\0"
"fcntl\0"
"mpx\0"
"setpgid\0"
"ulimit\0"
"oldolduname\0"
"umask\0"
"chroot\0"
"ustat\0"
"dup2\0"
"getppid\0"
"getpgrp\0"
"setsid\0"
"sigaction\0"
"sgetmask\0"
"ssetmask\0"
"setreuid\0"
"setregid\0"
"sigsuspend\0"
"sigpending\0"
"sethostname\0"
"setrlimit\0"
"getrlimit\0"
"getrusage\0"
"gettimeofday\0"
"settimeofday\0"
"getgroups\0"
"setgroups\0"
"reserved82\0"
"symlink\0"
"oldlstat\0"
"readlink\0"
"uselib\0"
"swapon\0"
"reboot\0"
"readdir\0"
"old_mmap\0"
"munmap\0"
"truncate\0"
"ftruncate\0"
"fchmod\0"
"fchown\0"
"getpriority\0"
"setpriority\0"
"profil\0"
"statfs\0"
"fstatfs\0"
"ioperm\0"
"socketcall\0"
"syslog\0"
"setitimer\0"
"getitimer\0"
"stat\0"
"lstat\0"
"fstat\0"
"olduname\0"
"iopl\0"
"vhangup\0"
"idle\0"
"vm86\0"
"wait4\0"
"swapoff\0"
"sysinfo\0"
"ipc\0"
"fsync\0"
"sigreturn\0"
"clone\0"
"setdomainname\0"
"uname\0"
"modify_ldt\0"
"adjtimex\0"
"mprotect\0"
"sigprocmask\0"
"create_module\0"
"init_module\0"
"delete_module\0"
"get_kernel_syms\0"
"quotactl\0"
"getpgid\0"
"fchdir\0"
"bdflush\0"
"sysfs\0"
"personality\0"
"afs_syscall\0"
"setfsuid\0"
"setfsgid\0"
"_llseek\0"
"getdents\0"
"_newselect\0"
"flock\0"
"msync\0"
"readv\0"
"writev\0"
"cacheflush\0"
"cachectl\0"
"sysmips\0"
"setup\0"
"getsid\0"
"fdatasync\0"
"_sysctl\0"
"mlock\0"
"munlock\0"
"mlockall\0"
"munlockall\0"
"sched_setparam\0"
"sched_getparam\0"
"sched_setscheduler\0"
"sched_getscheduler\0"
"sched_yield\0"
"sched_get_priority_max\0"
"sched_get_priority_min\0"
"sched_rr_get_interval\0"
"nanosleep\0"
"mremap\0"
"accept\0"
"bind\0"
"connect\0"
"getpeername\0"
"getsockname\0"
"getsockopt\0"
"listen\0"
"recv\0"
"recvfrom\0"
"recvmsg\0"
"send\0"
"sendmsg\0"
"sendto\0"
"setsockopt\0"
"shutdown\0"
"socket\0"
"socketpair\0"
"setresuid\0"
"getresuid\0"
"query_module\0"
"poll\0"
"nfsservctl\0"
"setresgid\0"
"getresgid\0"
"prctl\0"
"rt_sigreturn\0"
"rt_sigaction\0"
"rt_sigprocmask\0"
"rt_sigpending\0"
"rt_sigtimedwait\0"
"rt_sigqueueinfo\0"
"rt_sigsuspend\0"
"pread\0"
"pwrite\0"
"chown\0"
"getcwd\0"
"capget\0"
"capset\0"
"sigaltstatck\0"
"sendfile\0"
"mmap\0"
"truncate64\0"
"ftruncate64\0"
"stat64\0"
"lstat64\0"
"fstat64\0"
"pivot_root\0"
"mincore\0"
"madvise\0"
"getdents64\0"
"fcntl64\0"
"gettid\0"
"readahead\0"
"setxattr\0"
"lsetxattr\0"
"fsetxattr\0"
"getxattr\0"
"lgetxattr\0"
"fgetxattr\0"
"listxattr\0"
"llistxattr\0"
"flistxattr\0"
"removexattr\0"
"lremovexattr\0"
"fremovexattr\0"
"tkill\0"
"sendfile64\0"
"futex\0"
"sched_setaffinity\0"
"sched_getaffinity\0"
"io_setup\0"
"io_destroy\0"
"io_getevents\0"
"io_submit\0"
"io_cancel\0"
"exit_group\0"
"lookup_dcookie\0"
"epoll_create\0"
"epoll_ctl\0"
"epoll_wait\0"
"remap_file_pages\0"
"set_tid_address\0"
"restart_syscall\0"
"fadvise64_64\0"
"statfs64\0"
"fstatfs64\0"
"timer_create\0"
"timer_settime\0"
"timer_gettime\0"
"timer_getoverrun\0"
"timer_delete\0"
"clock_settime\0"
"clock_gettime\0"
"clock_getres\0"
"clock_nanosleep\0"
"tgkill\0"
"utimes\0"
"mbind\0"
"mq_open\0"
"mq_unlink\0"
"mq_timedsend\0"
"mq_timedreceive\0"
"mq_notify\0"
"mq_getsetattr\0"
"waitid\0"
"add_key\0"
"request_key\0"
"keyctl\0"
"set_thread_area\0"
"inotify_init\0"
"inotify_add_watch\0"
"inotify_rm_watch\0"
"migrate_pages\0"
"openat\0"
"mkdirat\0"
"mknodat\0"
"fchownat\0"
"futimesat\0"
"newfstatat\0"
"unlinkat\0"
"renameat\0"
"linkat\0"
"symlinkat\0"
"readlinkat\0"
"fchmodat\0"
"faccessat\0"
"pselect6\0"
"ppoll\0"
"unshare\0"
"splice\0"
"sync_file_range\0"
"tee\0"
"vmsplice\0"
"move_pages\0"
"set_robust_list\0"
"get_robust_list\0"
"kexec_load\0"
"getcpu\0"
"epoll_pwait\0"
"ioprio_set\0"
"ioprio_get\0"
"utimensat\0"
"signalfd\0"
"timerfd\0"
"eventfd\0"
"fallocate\0"
"timerfd_create\0"
"timerfd_gettime\0"
"timerfd_settime\0"
"signalfd4\0"
"eventfd2\0"
"epoll_create1\0"
"dup3\0"
"pipe2\0"
"inotify_init1\0"
"preadv\0"
"pwritev\0"
"rt_tgsigqueueinfo\0"
"perf_event_open\0"
"accept4\0"
"recvmmsg\0"
"fanotify_init\0"
"fanotify_mark\0"
"prlimit64\0"
"name_to_handle_at\0"
"open_by_handle_at\0"
"clock_adjtime\0"
"syncfs\0"
"sendmmsg\0"
"setns\0"
"process_vm_readv\0"
"process_vm_writev\0"
"";
/*
longest string: 22
total concatenated string length: 3231
pointer overhead: 2720
strings + overhead: 5951
total size aligned to max strlen 7820
*/
