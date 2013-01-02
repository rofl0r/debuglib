static const syscalldef syscalldefs[] = {
	[SYSCALL_OR_NUM(5000, SYS_read)]	 = MAKE_UINT16(3, 1),
	[SYSCALL_OR_NUM(5001, SYS_write)]	 = MAKE_UINT16(3, 6),
	[SYSCALL_OR_NUM(5002, SYS_open)]	 = MAKE_UINT16(3, 12),
	[SYSCALL_OR_NUM(5003, SYS_close)]	 = MAKE_UINT16(1, 17),
	[SYSCALL_OR_NUM(5004, SYS_stat)]	 = MAKE_UINT16(2, 23),
	[SYSCALL_OR_NUM(5005, SYS_fstat)]	 = MAKE_UINT16(2, 28),
	[SYSCALL_OR_NUM(5006, SYS_lstat)]	 = MAKE_UINT16(2, 34),
	[SYSCALL_OR_NUM(5007, SYS_poll)]	 = MAKE_UINT16(3, 40),
	[SYSCALL_OR_NUM(5008, SYS_lseek)]	 = MAKE_UINT16(3, 45),
	[SYSCALL_OR_NUM(5009, SYS_mmap)]	 = MAKE_UINT16(6, 51),
	[SYSCALL_OR_NUM(5010, SYS_mprotect)]	 = MAKE_UINT16(3, 56),
	[SYSCALL_OR_NUM(5011, SYS_munmap)]	 = MAKE_UINT16(2, 65),
	[SYSCALL_OR_NUM(5012, SYS_brk)]	 = MAKE_UINT16(1, 72),
	[SYSCALL_OR_NUM(5013, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 76),
	[SYSCALL_OR_NUM(5014, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 89),
	[SYSCALL_OR_NUM(5015, SYS_ioctl)]	 = MAKE_UINT16(3, 104),
	[SYSCALL_OR_NUM(5016, SYS_pread)]	 = MAKE_UINT16(6, 110),
	[SYSCALL_OR_NUM(5017, SYS_pwrite)]	 = MAKE_UINT16(6, 116),
	[SYSCALL_OR_NUM(5018, SYS_readv)]	 = MAKE_UINT16(3, 123),
	[SYSCALL_OR_NUM(5019, SYS_writev)]	 = MAKE_UINT16(3, 129),
	[SYSCALL_OR_NUM(5020, SYS_access)]	 = MAKE_UINT16(2, 136),
	[SYSCALL_OR_NUM(5021, SYS_pipe)]	 = MAKE_UINT16(1, 143),
	[SYSCALL_OR_NUM(5022, SYS__newselect)]	 = MAKE_UINT16(5, 148),
	[SYSCALL_OR_NUM(5023, SYS_sched_yield)]	 = MAKE_UINT16(0, 159),
	[SYSCALL_OR_NUM(5024, SYS_mremap)]	 = MAKE_UINT16(5, 171),
	[SYSCALL_OR_NUM(5025, SYS_msync)]	 = MAKE_UINT16(3, 178),
	[SYSCALL_OR_NUM(5026, SYS_mincore)]	 = MAKE_UINT16(3, 184),
	[SYSCALL_OR_NUM(5027, SYS_madvise)]	 = MAKE_UINT16(3, 192),
	[SYSCALL_OR_NUM(5028, SYS_shmget)]	 = MAKE_UINT16(3, 200),
	[SYSCALL_OR_NUM(5029, SYS_shmgat)]	 = MAKE_UINT16(3, 207),
	[SYSCALL_OR_NUM(5030, SYS_shmctl)]	 = MAKE_UINT16(3, 214),
	[SYSCALL_OR_NUM(5031, SYS_dup)]	 = MAKE_UINT16(1, 221),
	[SYSCALL_OR_NUM(5032, SYS_dup2)]	 = MAKE_UINT16(2, 225),
	[SYSCALL_OR_NUM(5033, SYS_pause)]	 = MAKE_UINT16(0, 230),
	[SYSCALL_OR_NUM(5034, SYS_nanosleep)]	 = MAKE_UINT16(2, 236),
	[SYSCALL_OR_NUM(5035, SYS_getitimer)]	 = MAKE_UINT16(2, 246),
	[SYSCALL_OR_NUM(5036, SYS_setitimer)]	 = MAKE_UINT16(3, 256),
	[SYSCALL_OR_NUM(5037, SYS_alarm)]	 = MAKE_UINT16(1, 266),
	[SYSCALL_OR_NUM(5038, SYS_getpid)]	 = MAKE_UINT16(0, 272),
	[SYSCALL_OR_NUM(5039, SYS_sendfile)]	 = MAKE_UINT16(4, 279),
	[SYSCALL_OR_NUM(5040, SYS_socketcall)]	 = MAKE_UINT16(2, 288),
	[SYSCALL_OR_NUM(5041, SYS_connect)]	 = MAKE_UINT16(3, 299),
	[SYSCALL_OR_NUM(5042, SYS_accept)]	 = MAKE_UINT16(3, 307),
	[SYSCALL_OR_NUM(5043, SYS_sendto)]	 = MAKE_UINT16(6, 314),
	[SYSCALL_OR_NUM(5044, SYS_recvfrom)]	 = MAKE_UINT16(6, 321),
	[SYSCALL_OR_NUM(5045, SYS_sendmsg)]	 = MAKE_UINT16(3, 330),
	[SYSCALL_OR_NUM(5046, SYS_recvmsg)]	 = MAKE_UINT16(3, 338),
	[SYSCALL_OR_NUM(5047, SYS_shutdown)]	 = MAKE_UINT16(2, 346),
	[SYSCALL_OR_NUM(5048, SYS_bind)]	 = MAKE_UINT16(3, 355),
	[SYSCALL_OR_NUM(5049, SYS_listen)]	 = MAKE_UINT16(2, 360),
	[SYSCALL_OR_NUM(5050, SYS_getsockname)]	 = MAKE_UINT16(3, 367),
	[SYSCALL_OR_NUM(5051, SYS_getpeername)]	 = MAKE_UINT16(3, 379),
	[SYSCALL_OR_NUM(5052, SYS_socketpair)]	 = MAKE_UINT16(4, 391),
	[SYSCALL_OR_NUM(5053, SYS_setsockopt)]	 = MAKE_UINT16(5, 402),
	[SYSCALL_OR_NUM(5054, SYS_getsockopt)]	 = MAKE_UINT16(5, 413),
	[SYSCALL_OR_NUM(5055, SYS_clone)]	 = MAKE_UINT16(2, 424),
	[SYSCALL_OR_NUM(5056, SYS_fork)]	 = MAKE_UINT16(0, 430),
	[SYSCALL_OR_NUM(5057, SYS_execve)]	 = MAKE_UINT16(3, 435),
	[SYSCALL_OR_NUM(5058, SYS_exit)]	 = MAKE_UINT16(1, 442),
	[SYSCALL_OR_NUM(5059, SYS_wait4)]	 = MAKE_UINT16(4, 447),
	[SYSCALL_OR_NUM(5060, SYS_kill)]	 = MAKE_UINT16(2, 453),
	[SYSCALL_OR_NUM(5061, SYS_uname)]	 = MAKE_UINT16(1, 458),
	[SYSCALL_OR_NUM(5062, SYS_semget)]	 = MAKE_UINT16(3, 464),
	[SYSCALL_OR_NUM(5063, SYS_semop)]	 = MAKE_UINT16(3, 471),
	[SYSCALL_OR_NUM(5064, SYS_semctl)]	 = MAKE_UINT16(4, 477),
	[SYSCALL_OR_NUM(5065, SYS_shmdt)]	 = MAKE_UINT16(1, 484),
	[SYSCALL_OR_NUM(5066, SYS_msgget)]	 = MAKE_UINT16(2, 490),
	[SYSCALL_OR_NUM(5067, SYS_msgsnd)]	 = MAKE_UINT16(4, 497),
	[SYSCALL_OR_NUM(5068, SYS_msgrcv)]	 = MAKE_UINT16(5, 504),
	[SYSCALL_OR_NUM(5069, SYS_msgctl)]	 = MAKE_UINT16(3, 511),
	[SYSCALL_OR_NUM(5070, SYS_fcntl)]	 = MAKE_UINT16(3, 518),
	[SYSCALL_OR_NUM(5071, SYS_flock)]	 = MAKE_UINT16(2, 524),
	[SYSCALL_OR_NUM(5072, SYS_fsync)]	 = MAKE_UINT16(1, 530),
	[SYSCALL_OR_NUM(5073, SYS_fdatasync)]	 = MAKE_UINT16(1, 536),
	[SYSCALL_OR_NUM(5074, SYS_truncate)]	 = MAKE_UINT16(2, 546),
	[SYSCALL_OR_NUM(5075, SYS_ftruncate)]	 = MAKE_UINT16(2, 555),
	[SYSCALL_OR_NUM(5076, SYS_getdents)]	 = MAKE_UINT16(3, 565),
	[SYSCALL_OR_NUM(5077, SYS_getcwd)]	 = MAKE_UINT16(2, 574),
	[SYSCALL_OR_NUM(5078, SYS_chdir)]	 = MAKE_UINT16(1, 581),
	[SYSCALL_OR_NUM(5079, SYS_fchdir)]	 = MAKE_UINT16(1, 587),
	[SYSCALL_OR_NUM(5080, SYS_rename)]	 = MAKE_UINT16(2, 594),
	[SYSCALL_OR_NUM(5081, SYS_mkdir)]	 = MAKE_UINT16(2, 601),
	[SYSCALL_OR_NUM(5082, SYS_rmdir)]	 = MAKE_UINT16(1, 607),
	[SYSCALL_OR_NUM(5083, SYS_creat)]	 = MAKE_UINT16(2, 613),
	[SYSCALL_OR_NUM(5084, SYS_link)]	 = MAKE_UINT16(2, 619),
	[SYSCALL_OR_NUM(5085, SYS_unlink)]	 = MAKE_UINT16(1, 624),
	[SYSCALL_OR_NUM(5086, SYS_symlink)]	 = MAKE_UINT16(2, 631),
	[SYSCALL_OR_NUM(5087, SYS_readlink)]	 = MAKE_UINT16(3, 639),
	[SYSCALL_OR_NUM(5088, SYS_chmod)]	 = MAKE_UINT16(2, 648),
	[SYSCALL_OR_NUM(5089, SYS_fchmod)]	 = MAKE_UINT16(2, 654),
	[SYSCALL_OR_NUM(5090, SYS_chown)]	 = MAKE_UINT16(3, 661),
	[SYSCALL_OR_NUM(5091, SYS_fchown)]	 = MAKE_UINT16(3, 667),
	[SYSCALL_OR_NUM(5092, SYS_lchown)]	 = MAKE_UINT16(3, 674),
	[SYSCALL_OR_NUM(5093, SYS_umask)]	 = MAKE_UINT16(1, 681),
	[SYSCALL_OR_NUM(5094, SYS_gettimeofday)]	 = MAKE_UINT16(2, 687),
	[SYSCALL_OR_NUM(5095, SYS_getrlimit)]	 = MAKE_UINT16(2, 700),
	[SYSCALL_OR_NUM(5096, SYS_getrusage)]	 = MAKE_UINT16(2, 710),
	[SYSCALL_OR_NUM(5097, SYS_sysinfo)]	 = MAKE_UINT16(1, 720),
	[SYSCALL_OR_NUM(5098, SYS_times)]	 = MAKE_UINT16(1, 728),
	[SYSCALL_OR_NUM(5099, SYS_ptrace)]	 = MAKE_UINT16(4, 734),
	[SYSCALL_OR_NUM(5100, SYS_getuid)]	 = MAKE_UINT16(0, 741),
	[SYSCALL_OR_NUM(5101, SYS_syslog)]	 = MAKE_UINT16(3, 748),
	[SYSCALL_OR_NUM(5102, SYS_getgid)]	 = MAKE_UINT16(0, 755),
	[SYSCALL_OR_NUM(5103, SYS_setuid)]	 = MAKE_UINT16(1, 762),
	[SYSCALL_OR_NUM(5104, SYS_setgid)]	 = MAKE_UINT16(1, 769),
	[SYSCALL_OR_NUM(5105, SYS_geteuid)]	 = MAKE_UINT16(0, 776),
	[SYSCALL_OR_NUM(5106, SYS_getegid)]	 = MAKE_UINT16(0, 784),
	[SYSCALL_OR_NUM(5107, SYS_setpgid)]	 = MAKE_UINT16(2, 792),
	[SYSCALL_OR_NUM(5108, SYS_getppid)]	 = MAKE_UINT16(0, 800),
	[SYSCALL_OR_NUM(5109, SYS_getpgrp)]	 = MAKE_UINT16(0, 808),
	[SYSCALL_OR_NUM(5110, SYS_setsid)]	 = MAKE_UINT16(0, 816),
	[SYSCALL_OR_NUM(5111, SYS_setreuid)]	 = MAKE_UINT16(2, 823),
	[SYSCALL_OR_NUM(5112, SYS_setregid)]	 = MAKE_UINT16(2, 832),
	[SYSCALL_OR_NUM(5113, SYS_getgroups)]	 = MAKE_UINT16(2, 841),
	[SYSCALL_OR_NUM(5114, SYS_setgroups)]	 = MAKE_UINT16(2, 851),
	[SYSCALL_OR_NUM(5115, SYS_setresuid)]	 = MAKE_UINT16(3, 861),
	[SYSCALL_OR_NUM(5116, SYS_getresuid)]	 = MAKE_UINT16(3, 871),
	[SYSCALL_OR_NUM(5117, SYS_setresgid)]	 = MAKE_UINT16(3, 881),
	[SYSCALL_OR_NUM(5118, SYS_getresgid)]	 = MAKE_UINT16(3, 891),
	[SYSCALL_OR_NUM(5119, SYS_getpgid)]	 = MAKE_UINT16(0, 901),
	[SYSCALL_OR_NUM(5120, SYS_setfsuid)]	 = MAKE_UINT16(1, 909),
	[SYSCALL_OR_NUM(5121, SYS_setfsgid)]	 = MAKE_UINT16(1, 918),
	[SYSCALL_OR_NUM(5122, SYS_getsid)]	 = MAKE_UINT16(1, 927),
	[SYSCALL_OR_NUM(5123, SYS_capget)]	 = MAKE_UINT16(2, 934),
	[SYSCALL_OR_NUM(5124, SYS_capset)]	 = MAKE_UINT16(2, 941),
	[SYSCALL_OR_NUM(5125, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 948),
	[SYSCALL_OR_NUM(5126, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 962),
	[SYSCALL_OR_NUM(5127, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 978),
	[SYSCALL_OR_NUM(5128, SYS_rt_siguspend)]	 = MAKE_UINT16(2, 994),
	[SYSCALL_OR_NUM(5129, SYS_sigaltstatck)]	 = MAKE_UINT16(2, 1007),
	[SYSCALL_OR_NUM(5130, SYS_utime)]	 = MAKE_UINT16(2, 1020),
	[SYSCALL_OR_NUM(5131, SYS_mknod)]	 = MAKE_UINT16(3, 1026),
	[SYSCALL_OR_NUM(5132, SYS_personality)]	 = MAKE_UINT16(1, 1032),
	[SYSCALL_OR_NUM(5133, SYS_ustat)]	 = MAKE_UINT16(2, 1044),
	[SYSCALL_OR_NUM(5134, SYS_statfs)]	 = MAKE_UINT16(3, 1050),
	[SYSCALL_OR_NUM(5135, SYS_fstatfs)]	 = MAKE_UINT16(3, 1057),
	[SYSCALL_OR_NUM(5136, SYS_sysfs)]	 = MAKE_UINT16(5, 1065),
	[SYSCALL_OR_NUM(5137, SYS_getpriority)]	 = MAKE_UINT16(2, 1071),
	[SYSCALL_OR_NUM(5138, SYS_setpriority)]	 = MAKE_UINT16(3, 1083),
	[SYSCALL_OR_NUM(5139, SYS_sched_setparam)]	 = MAKE_UINT16(2, 1095),
	[SYSCALL_OR_NUM(5140, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1110),
	[SYSCALL_OR_NUM(5141, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1125),
	[SYSCALL_OR_NUM(5142, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1144),
	[SYSCALL_OR_NUM(5143, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1163),
	[SYSCALL_OR_NUM(5144, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1186),
	[SYSCALL_OR_NUM(5145, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1209),
	[SYSCALL_OR_NUM(5146, SYS_mlock)]	 = MAKE_UINT16(2, 1231),
	[SYSCALL_OR_NUM(5147, SYS_munlock)]	 = MAKE_UINT16(2, 1237),
	[SYSCALL_OR_NUM(5148, SYS_mlockall)]	 = MAKE_UINT16(1, 1245),
	[SYSCALL_OR_NUM(5149, SYS_munlockall)]	 = MAKE_UINT16(0, 1254),
	[SYSCALL_OR_NUM(5150, SYS_vhangup)]	 = MAKE_UINT16(0, 1265),
	[SYSCALL_OR_NUM(5151, SYS_pivot_root)]	 = MAKE_UINT16(2, 1273),
	[SYSCALL_OR_NUM(5152, SYS__sysctl)]	 = MAKE_UINT16(1, 1284),
	[SYSCALL_OR_NUM(5153, SYS_prctl)]	 = MAKE_UINT16(5, 1292),
	[SYSCALL_OR_NUM(5154, SYS_adjtimex)]	 = MAKE_UINT16(1, 1298),
	[SYSCALL_OR_NUM(5155, SYS_setrlimit)]	 = MAKE_UINT16(2, 1307),
	[SYSCALL_OR_NUM(5156, SYS_chroot)]	 = MAKE_UINT16(1, 1317),
	[SYSCALL_OR_NUM(5157, SYS_sync)]	 = MAKE_UINT16(0, 1324),
	[SYSCALL_OR_NUM(5158, SYS_acct)]	 = MAKE_UINT16(1, 1329),
	[SYSCALL_OR_NUM(5159, SYS_settimeofday)]	 = MAKE_UINT16(2, 1334),
	[SYSCALL_OR_NUM(5160, SYS_mount)]	 = MAKE_UINT16(5, 1347),
	[SYSCALL_OR_NUM(5161, SYS_umount)]	 = MAKE_UINT16(2, 1353),
	[SYSCALL_OR_NUM(5162, SYS_swapon)]	 = MAKE_UINT16(2, 1360),
	[SYSCALL_OR_NUM(5163, SYS_swapoff)]	 = MAKE_UINT16(1, 1367),
	[SYSCALL_OR_NUM(5164, SYS_reboot)]	 = MAKE_UINT16(4, 1375),
	[SYSCALL_OR_NUM(5165, SYS_sethostname)]	 = MAKE_UINT16(2, 1382),
	[SYSCALL_OR_NUM(5166, SYS_setdomainname)]	 = MAKE_UINT16(2, 1394),
	[SYSCALL_OR_NUM(5167, SYS_create_module)]	 = MAKE_UINT16(2, 1408),
	[SYSCALL_OR_NUM(5168, SYS_init_module)]	 = MAKE_UINT16(4, 1422),
	[SYSCALL_OR_NUM(5169, SYS_delete_module)]	 = MAKE_UINT16(1, 1434),
	[SYSCALL_OR_NUM(5170, SYS_get_kernel_syms)]	 = MAKE_UINT16(1, 1448),
	[SYSCALL_OR_NUM(5171, SYS_query_module)]	 = MAKE_UINT16(5, 1464),
	[SYSCALL_OR_NUM(5172, SYS_quotactl)]	 = MAKE_UINT16(4, 1477),
	[SYSCALL_OR_NUM(5173, SYS_nfsservctl)]	 = MAKE_UINT16(3, 1486),
	[SYSCALL_OR_NUM(5174, SYS_getpmsg)]	 = MAKE_UINT16(5, 1497),
	[SYSCALL_OR_NUM(5175, SYS_putpmsg)]	 = MAKE_UINT16(5, 1505),
	[SYSCALL_OR_NUM(5176, SYS_afs_syscall)]	 = MAKE_UINT16(0, 1513),
	[SYSCALL_OR_NUM(5177, SYS_reserved177)]	 = MAKE_UINT16(0, 1525),
	[SYSCALL_OR_NUM(5178, SYS_gettid)]	 = MAKE_UINT16(0, 1537),
	[SYSCALL_OR_NUM(5179, SYS_readahead)]	 = MAKE_UINT16(3, 1544),
	[SYSCALL_OR_NUM(5180, SYS_setxattr)]	 = MAKE_UINT16(5, 1554),
	[SYSCALL_OR_NUM(5181, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1563),
	[SYSCALL_OR_NUM(5182, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1573),
	[SYSCALL_OR_NUM(5183, SYS_getxattr)]	 = MAKE_UINT16(4, 1583),
	[SYSCALL_OR_NUM(5184, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1592),
	[SYSCALL_OR_NUM(5185, SYS_fgetxattr)]	 = MAKE_UINT16(4, 1602),
	[SYSCALL_OR_NUM(5186, SYS_listxattr)]	 = MAKE_UINT16(3, 1612),
	[SYSCALL_OR_NUM(5187, SYS_llistxattr)]	 = MAKE_UINT16(3, 1622),
	[SYSCALL_OR_NUM(5188, SYS_flistxattr)]	 = MAKE_UINT16(3, 1633),
	[SYSCALL_OR_NUM(5189, SYS_removexattr)]	 = MAKE_UINT16(2, 1644),
	[SYSCALL_OR_NUM(5190, SYS_lremovexattr)]	 = MAKE_UINT16(2, 1656),
	[SYSCALL_OR_NUM(5191, SYS_fremovexattr)]	 = MAKE_UINT16(2, 1669),
	[SYSCALL_OR_NUM(5192, SYS_tkill)]	 = MAKE_UINT16(2, 1682),
	[SYSCALL_OR_NUM(5193, SYS_time)]	 = MAKE_UINT16(1, 1688),
	[SYSCALL_OR_NUM(5194, SYS_futex)]	 = MAKE_UINT16(6, 1693),
	[SYSCALL_OR_NUM(5195, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 1699),
	[SYSCALL_OR_NUM(5196, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 1717),
	[SYSCALL_OR_NUM(5197, SYS_cacheflush)]	 = MAKE_UINT16(3, 1735),
	[SYSCALL_OR_NUM(5198, SYS_cachectl)]	 = MAKE_UINT16(3, 1746),
	[SYSCALL_OR_NUM(5199, SYS_sysmips)]	 = MAKE_UINT16(4, 1755),
	[SYSCALL_OR_NUM(5200, SYS_io_setup)]	 = MAKE_UINT16(2, 1763),
	[SYSCALL_OR_NUM(5201, SYS_io_destroy)]	 = MAKE_UINT16(1, 1772),
	[SYSCALL_OR_NUM(5202, SYS_io_getevents)]	 = MAKE_UINT16(5, 1783),
	[SYSCALL_OR_NUM(5203, SYS_io_submit)]	 = MAKE_UINT16(3, 1796),
	[SYSCALL_OR_NUM(5204, SYS_io_cancel)]	 = MAKE_UINT16(3, 1806),
	[SYSCALL_OR_NUM(5205, SYS_exit_group)]	 = MAKE_UINT16(1, 1816),
	[SYSCALL_OR_NUM(5206, SYS_lookup_dcookie)]	 = MAKE_UINT16(3, 1827),
	[SYSCALL_OR_NUM(5207, SYS_epoll_create)]	 = MAKE_UINT16(1, 1842),
	[SYSCALL_OR_NUM(5208, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 1855),
	[SYSCALL_OR_NUM(5209, SYS_epoll_wait)]	 = MAKE_UINT16(4, 1865),
	[SYSCALL_OR_NUM(5210, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 1876),
	[SYSCALL_OR_NUM(5211, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 1893),
	[SYSCALL_OR_NUM(5212, SYS_set_tid_address)]	 = MAKE_UINT16(1, 1906),
	[SYSCALL_OR_NUM(5213, SYS_restart_syscall)]	 = MAKE_UINT16(0, 1922),
	[SYSCALL_OR_NUM(5214, SYS_semtimedop)]	 = MAKE_UINT16(5, 1938),
	[SYSCALL_OR_NUM(5215, SYS_fadvise64_64)]	 = MAKE_UINT16(4, 1949),
	[SYSCALL_OR_NUM(5216, SYS_timer_create)]	 = MAKE_UINT16(3, 1962),
	[SYSCALL_OR_NUM(5217, SYS_timer_settime)]	 = MAKE_UINT16(4, 1975),
	[SYSCALL_OR_NUM(5218, SYS_timer_gettime)]	 = MAKE_UINT16(2, 1989),
	[SYSCALL_OR_NUM(5219, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2003),
	[SYSCALL_OR_NUM(5220, SYS_timer_delete)]	 = MAKE_UINT16(1, 2020),
	[SYSCALL_OR_NUM(5221, SYS_clock_settime)]	 = MAKE_UINT16(2, 2033),
	[SYSCALL_OR_NUM(5222, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2047),
	[SYSCALL_OR_NUM(5223, SYS_clock_getres)]	 = MAKE_UINT16(2, 2061),
	[SYSCALL_OR_NUM(5224, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2074),
	[SYSCALL_OR_NUM(5225, SYS_tgkill)]	 = MAKE_UINT16(3, 2090),
	[SYSCALL_OR_NUM(5226, SYS_utimes)]	 = MAKE_UINT16(2, 2097),
	[SYSCALL_OR_NUM(5227, SYS_mbind)]	 = MAKE_UINT16(6, 2104),
// XXXXXXX 	{ 0,	0,	NULL,			NULL		}, /* 5228 */
// XXXXXXX 	{ 0,	0,	NULL,			NULL		}, /* 5229 */
	[SYSCALL_OR_NUM(5230, SYS_mq_open)]	 = MAKE_UINT16(4, 2110),
	[SYSCALL_OR_NUM(5231, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2118),
	[SYSCALL_OR_NUM(5232, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2128),
	[SYSCALL_OR_NUM(5233, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2141),
	[SYSCALL_OR_NUM(5234, SYS_mq_notify)]	 = MAKE_UINT16(2, 2157),
	[SYSCALL_OR_NUM(5235, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2167),
	[SYSCALL_OR_NUM(5237, SYS_waitid)]	 = MAKE_UINT16(5, 2181),
	[SYSCALL_OR_NUM(5239, SYS_add_key)]	 = MAKE_UINT16(5, 2188),
	[SYSCALL_OR_NUM(5230, SYS_request_key)]	 = MAKE_UINT16(4, 2196),
	[SYSCALL_OR_NUM(5241, SYS_keyctl)]	 = MAKE_UINT16(5, 2208),
	[SYSCALL_OR_NUM(5242, SYS_set_thread_area)]	 = MAKE_UINT16(1, 2215),
	[SYSCALL_OR_NUM(5243, SYS_inotify_init)]	 = MAKE_UINT16(0, 2231),
	[SYSCALL_OR_NUM(5244, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2244),
	[SYSCALL_OR_NUM(5245, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2262),
	[SYSCALL_OR_NUM(5246, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2279),
	[SYSCALL_OR_NUM(5247, SYS_openat)]	 = MAKE_UINT16(4, 2293),
	[SYSCALL_OR_NUM(5248, SYS_mkdirat)]	 = MAKE_UINT16(3, 2300),
	[SYSCALL_OR_NUM(5249, SYS_mknodat)]	 = MAKE_UINT16(4, 2308),
	[SYSCALL_OR_NUM(5250, SYS_fchownat)]	 = MAKE_UINT16(5, 2316),
	[SYSCALL_OR_NUM(5251, SYS_futimesat)]	 = MAKE_UINT16(3, 2325),
	[SYSCALL_OR_NUM(5252, SYS_newfstatat)]	 = MAKE_UINT16(4, 2335),
	[SYSCALL_OR_NUM(5253, SYS_unlinkat)]	 = MAKE_UINT16(3, 2346),
	[SYSCALL_OR_NUM(5254, SYS_renameat)]	 = MAKE_UINT16(4, 2355),
	[SYSCALL_OR_NUM(5255, SYS_linkat)]	 = MAKE_UINT16(5, 2364),
	[SYSCALL_OR_NUM(5256, SYS_symlinkat)]	 = MAKE_UINT16(3, 2371),
	[SYSCALL_OR_NUM(5257, SYS_readlinkat)]	 = MAKE_UINT16(4, 2381),
	[SYSCALL_OR_NUM(5258, SYS_fchmodat)]	 = MAKE_UINT16(3, 2392),
	[SYSCALL_OR_NUM(5259, SYS_faccessat)]	 = MAKE_UINT16(3, 2401),
	[SYSCALL_OR_NUM(5260, SYS_pselect6)]	 = MAKE_UINT16(6, 2411),
	[SYSCALL_OR_NUM(5261, SYS_ppoll)]	 = MAKE_UINT16(5, 2420),
	[SYSCALL_OR_NUM(5262, SYS_unshare)]	 = MAKE_UINT16(1, 2426),
	[SYSCALL_OR_NUM(5263, SYS_splice)]	 = MAKE_UINT16(6, 2434),
	[SYSCALL_OR_NUM(5264, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2441),
	[SYSCALL_OR_NUM(5265, SYS_tee)]	 = MAKE_UINT16(4, 2457),
	[SYSCALL_OR_NUM(5266, SYS_vmsplice)]	 = MAKE_UINT16(4, 2461),
	[SYSCALL_OR_NUM(5267, SYS_move_pages)]	 = MAKE_UINT16(6, 2470),
	[SYSCALL_OR_NUM(5268, SYS_set_robust_list)]	 = MAKE_UINT16(2, 2481),
	[SYSCALL_OR_NUM(5269, SYS_get_robust_list)]	 = MAKE_UINT16(3, 2497),
	[SYSCALL_OR_NUM(5270, SYS_kexec_load)]	 = MAKE_UINT16(4, 2513),
	[SYSCALL_OR_NUM(5271, SYS_getcpu)]	 = MAKE_UINT16(3, 2524),
	[SYSCALL_OR_NUM(5272, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2531),
	[SYSCALL_OR_NUM(5273, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2543),
	[SYSCALL_OR_NUM(5274, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2554),
	[SYSCALL_OR_NUM(5275, SYS_utimensat)]	 = MAKE_UINT16(4, 2565),
	[SYSCALL_OR_NUM(5276, SYS_signalfd)]	 = MAKE_UINT16(3, 2575),
	[SYSCALL_OR_NUM(5278, SYS_eventfd)]	 = MAKE_UINT16(1, 2584),
	[SYSCALL_OR_NUM(5279, SYS_fallocate)]	 = MAKE_UINT16(6, 2592),
	[SYSCALL_OR_NUM(5280, SYS_timerfd_create)]	 = MAKE_UINT16(2, 2602),
	[SYSCALL_OR_NUM(5281, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 2617),
	[SYSCALL_OR_NUM(5282, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 2633),
	[SYSCALL_OR_NUM(5283, SYS_signalfd4)]	 = MAKE_UINT16(4, 2649),
	[SYSCALL_OR_NUM(5284, SYS_eventfd2)]	 = MAKE_UINT16(2, 2659),
	[SYSCALL_OR_NUM(5285, SYS_epoll_create1)]	 = MAKE_UINT16(1, 2668),
	[SYSCALL_OR_NUM(5286, SYS_dup3)]	 = MAKE_UINT16(3, 2682),
	[SYSCALL_OR_NUM(5287, SYS_pipe2)]	 = MAKE_UINT16(2, 2687),
	[SYSCALL_OR_NUM(5288, SYS_inotify_init1)]	 = MAKE_UINT16(1, 2693),
	[SYSCALL_OR_NUM(5289, SYS_preadv)]	 = MAKE_UINT16(5, 2707),
	[SYSCALL_OR_NUM(5290, SYS_pwritev)]	 = MAKE_UINT16(5, 2714),
	[SYSCALL_OR_NUM(5291, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 2722),
	[SYSCALL_OR_NUM(5292, SYS_perf_event_open)]	 = MAKE_UINT16(5, 2740),
	[SYSCALL_OR_NUM(5293, SYS_accept4)]	 = MAKE_UINT16(4, 2756),
	[SYSCALL_OR_NUM(5294, SYS_recvmmsg)]	 = MAKE_UINT16(5, 2764),
	[SYSCALL_OR_NUM(5295, SYS_fanotify_init)]	 = MAKE_UINT16(2, 2773),
	[SYSCALL_OR_NUM(5296, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 2787),
	[SYSCALL_OR_NUM(5297, SYS_prlimit64)]	 = MAKE_UINT16(4, 2801),
	[SYSCALL_OR_NUM(5298, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 2811),
	[SYSCALL_OR_NUM(5299, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 2829),
	[SYSCALL_OR_NUM(5300, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 2847),
	[SYSCALL_OR_NUM(5301, SYS_syncfs)]	 = MAKE_UINT16(1, 2861),
	[SYSCALL_OR_NUM(5302, SYS_sendmmsg)]	 = MAKE_UINT16(4, 2868),
	[SYSCALL_OR_NUM(5303, SYS_setns)]	 = MAKE_UINT16(2, 2877),
	[SYSCALL_OR_NUM(5304, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 2883),
	[SYSCALL_OR_NUM(5305, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 2900),
};

static const char syscallnames[] = "\0"
"read\0"
"write\0"
"open\0"
"close\0"
"stat\0"
"fstat\0"
"lstat\0"
"poll\0"
"lseek\0"
"mmap\0"
"mprotect\0"
"munmap\0"
"brk\0"
"rt_sigaction\0"
"rt_sigprocmask\0"
"ioctl\0"
"pread\0"
"pwrite\0"
"readv\0"
"writev\0"
"access\0"
"pipe\0"
"_newselect\0"
"sched_yield\0"
"mremap\0"
"msync\0"
"mincore\0"
"madvise\0"
"shmget\0"
"shmgat\0"
"shmctl\0"
"dup\0"
"dup2\0"
"pause\0"
"nanosleep\0"
"getitimer\0"
"setitimer\0"
"alarm\0"
"getpid\0"
"sendfile\0"
"socketcall\0"
"connect\0"
"accept\0"
"sendto\0"
"recvfrom\0"
"sendmsg\0"
"recvmsg\0"
"shutdown\0"
"bind\0"
"listen\0"
"getsockname\0"
"getpeername\0"
"socketpair\0"
"setsockopt\0"
"getsockopt\0"
"clone\0"
"fork\0"
"execve\0"
"exit\0"
"wait4\0"
"kill\0"
"uname\0"
"semget\0"
"semop\0"
"semctl\0"
"shmdt\0"
"msgget\0"
"msgsnd\0"
"msgrcv\0"
"msgctl\0"
"fcntl\0"
"flock\0"
"fsync\0"
"fdatasync\0"
"truncate\0"
"ftruncate\0"
"getdents\0"
"getcwd\0"
"chdir\0"
"fchdir\0"
"rename\0"
"mkdir\0"
"rmdir\0"
"creat\0"
"link\0"
"unlink\0"
"symlink\0"
"readlink\0"
"chmod\0"
"fchmod\0"
"chown\0"
"fchown\0"
"lchown\0"
"umask\0"
"gettimeofday\0"
"getrlimit\0"
"getrusage\0"
"sysinfo\0"
"times\0"
"ptrace\0"
"getuid\0"
"syslog\0"
"getgid\0"
"setuid\0"
"setgid\0"
"geteuid\0"
"getegid\0"
"setpgid\0"
"getppid\0"
"getpgrp\0"
"setsid\0"
"setreuid\0"
"setregid\0"
"getgroups\0"
"setgroups\0"
"setresuid\0"
"getresuid\0"
"setresgid\0"
"getresgid\0"
"getpgid\0"
"setfsuid\0"
"setfsgid\0"
"getsid\0"
"capget\0"
"capset\0"
"rt_sigpending\0"
"rt_sigtimedwait\0"
"rt_sigqueueinfo\0"
"rt_siguspend\0"
"sigaltstatck\0"
"utime\0"
"mknod\0"
"personality\0"
"ustat\0"
"statfs\0"
"fstatfs\0"
"sysfs\0"
"getpriority\0"
"setpriority\0"
"sched_setparam\0"
"sched_getparam\0"
"sched_setscheduler\0"
"sched_getscheduler\0"
"sched_get_priority_max\0"
"sched_get_priority_min\0"
"sched_rr_get_interval\0"
"mlock\0"
"munlock\0"
"mlockall\0"
"munlockall\0"
"vhangup\0"
"pivot_root\0"
"_sysctl\0"
"prctl\0"
"adjtimex\0"
"setrlimit\0"
"chroot\0"
"sync\0"
"acct\0"
"settimeofday\0"
"mount\0"
"umount\0"
"swapon\0"
"swapoff\0"
"reboot\0"
"sethostname\0"
"setdomainname\0"
"create_module\0"
"init_module\0"
"delete_module\0"
"get_kernel_syms\0"
"query_module\0"
"quotactl\0"
"nfsservctl\0"
"getpmsg\0"
"putpmsg\0"
"afs_syscall\0"
"reserved177\0"
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
"time\0"
"futex\0"
"sched_setaffinity\0"
"sched_getaffinity\0"
"cacheflush\0"
"cachectl\0"
"sysmips\0"
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
"rt_sigreturn\0"
"set_tid_address\0"
"restart_syscall\0"
"semtimedop\0"
"fadvise64_64\0"
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
total concatenated string length: 2917
pointer overhead: 2408
strings + overhead: 5325
total size aligned to max strlen 6923
*/
