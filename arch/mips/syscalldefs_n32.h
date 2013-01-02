static const syscalldef syscalldefs[] = {
	[SYSCALL_OR_NUM(6000, SYS_read)]	 = MAKE_UINT16(3, 1),
	[SYSCALL_OR_NUM(6001, SYS_write)]	 = MAKE_UINT16(3, 6),
	[SYSCALL_OR_NUM(6002, SYS_open)]	 = MAKE_UINT16(3, 12),
	[SYSCALL_OR_NUM(6003, SYS_close)]	 = MAKE_UINT16(1, 17),
	[SYSCALL_OR_NUM(6004, SYS_stat)]	 = MAKE_UINT16(2, 23),
	[SYSCALL_OR_NUM(6005, SYS_fstat)]	 = MAKE_UINT16(2, 28),
	[SYSCALL_OR_NUM(6006, SYS_lstat)]	 = MAKE_UINT16(2, 34),
	[SYSCALL_OR_NUM(6007, SYS_poll)]	 = MAKE_UINT16(3, 40),
	[SYSCALL_OR_NUM(6008, SYS_lseek)]	 = MAKE_UINT16(3, 45),
	[SYSCALL_OR_NUM(6009, SYS_mmap)]	 = MAKE_UINT16(6, 51),
	[SYSCALL_OR_NUM(6010, SYS_mprotect)]	 = MAKE_UINT16(3, 56),
	[SYSCALL_OR_NUM(6011, SYS_munmap)]	 = MAKE_UINT16(2, 65),
	[SYSCALL_OR_NUM(6012, SYS_brk)]	 = MAKE_UINT16(1, 72),
	[SYSCALL_OR_NUM(6013, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 76),
	[SYSCALL_OR_NUM(6014, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 89),
	[SYSCALL_OR_NUM(6015, SYS_ioctl)]	 = MAKE_UINT16(3, 104),
	[SYSCALL_OR_NUM(6016, SYS_pread)]	 = MAKE_UINT16(6, 110),
	[SYSCALL_OR_NUM(6017, SYS_pwrite)]	 = MAKE_UINT16(6, 116),
	[SYSCALL_OR_NUM(6018, SYS_readv)]	 = MAKE_UINT16(3, 123),
	[SYSCALL_OR_NUM(6019, SYS_writev)]	 = MAKE_UINT16(3, 129),
	[SYSCALL_OR_NUM(6020, SYS_access)]	 = MAKE_UINT16(2, 136),
	[SYSCALL_OR_NUM(6021, SYS_pipe)]	 = MAKE_UINT16(1, 143),
	[SYSCALL_OR_NUM(6022, SYS__newselect)]	 = MAKE_UINT16(5, 148),
	[SYSCALL_OR_NUM(6023, SYS_sched_yield)]	 = MAKE_UINT16(0, 159),
	[SYSCALL_OR_NUM(6024, SYS_mremap)]	 = MAKE_UINT16(5, 171),
	[SYSCALL_OR_NUM(6025, SYS_msync)]	 = MAKE_UINT16(3, 178),
	[SYSCALL_OR_NUM(6026, SYS_mincore)]	 = MAKE_UINT16(3, 184),
	[SYSCALL_OR_NUM(6027, SYS_madvise)]	 = MAKE_UINT16(3, 192),
	[SYSCALL_OR_NUM(6028, SYS_shmget)]	 = MAKE_UINT16(3, 200),
	[SYSCALL_OR_NUM(6029, SYS_shmgat)]	 = MAKE_UINT16(3, 207),
	[SYSCALL_OR_NUM(6030, SYS_shmctl)]	 = MAKE_UINT16(3, 214),
	[SYSCALL_OR_NUM(6031, SYS_dup)]	 = MAKE_UINT16(1, 221),
	[SYSCALL_OR_NUM(6032, SYS_dup2)]	 = MAKE_UINT16(2, 225),
	[SYSCALL_OR_NUM(6033, SYS_pause)]	 = MAKE_UINT16(0, 230),
	[SYSCALL_OR_NUM(6034, SYS_nanosleep)]	 = MAKE_UINT16(2, 236),
	[SYSCALL_OR_NUM(6035, SYS_getitimer)]	 = MAKE_UINT16(2, 246),
	[SYSCALL_OR_NUM(6036, SYS_setitimer)]	 = MAKE_UINT16(3, 256),
	[SYSCALL_OR_NUM(6037, SYS_alarm)]	 = MAKE_UINT16(1, 266),
	[SYSCALL_OR_NUM(6038, SYS_getpid)]	 = MAKE_UINT16(0, 272),
	[SYSCALL_OR_NUM(6039, SYS_sendfile)]	 = MAKE_UINT16(4, 279),
	[SYSCALL_OR_NUM(6040, SYS_socketcall)]	 = MAKE_UINT16(2, 288),
	[SYSCALL_OR_NUM(6041, SYS_connect)]	 = MAKE_UINT16(3, 299),
	[SYSCALL_OR_NUM(6042, SYS_accept)]	 = MAKE_UINT16(3, 307),
	[SYSCALL_OR_NUM(6043, SYS_sendto)]	 = MAKE_UINT16(6, 314),
	[SYSCALL_OR_NUM(6044, SYS_recvfrom)]	 = MAKE_UINT16(6, 321),
	[SYSCALL_OR_NUM(6045, SYS_sendmsg)]	 = MAKE_UINT16(3, 330),
	[SYSCALL_OR_NUM(6046, SYS_recvmsg)]	 = MAKE_UINT16(3, 338),
	[SYSCALL_OR_NUM(6047, SYS_shutdown)]	 = MAKE_UINT16(2, 346),
	[SYSCALL_OR_NUM(6048, SYS_bind)]	 = MAKE_UINT16(3, 355),
	[SYSCALL_OR_NUM(6049, SYS_listen)]	 = MAKE_UINT16(2, 360),
	[SYSCALL_OR_NUM(6050, SYS_getsockname)]	 = MAKE_UINT16(3, 367),
	[SYSCALL_OR_NUM(6051, SYS_getpeername)]	 = MAKE_UINT16(3, 379),
	[SYSCALL_OR_NUM(6052, SYS_socketpair)]	 = MAKE_UINT16(4, 391),
	[SYSCALL_OR_NUM(6053, SYS_setsockopt)]	 = MAKE_UINT16(5, 402),
	[SYSCALL_OR_NUM(6054, SYS_getsockopt)]	 = MAKE_UINT16(5, 413),
	[SYSCALL_OR_NUM(6055, SYS_clone)]	 = MAKE_UINT16(2, 424),
	[SYSCALL_OR_NUM(6056, SYS_fork)]	 = MAKE_UINT16(0, 430),
	[SYSCALL_OR_NUM(6057, SYS_execve)]	 = MAKE_UINT16(3, 435),
	[SYSCALL_OR_NUM(6058, SYS_exit)]	 = MAKE_UINT16(1, 442),
	[SYSCALL_OR_NUM(6059, SYS_wait4)]	 = MAKE_UINT16(4, 447),
	[SYSCALL_OR_NUM(6060, SYS_kill)]	 = MAKE_UINT16(2, 453),
	[SYSCALL_OR_NUM(6061, SYS_uname)]	 = MAKE_UINT16(1, 458),
	[SYSCALL_OR_NUM(6062, SYS_semget)]	 = MAKE_UINT16(3, 464),
	[SYSCALL_OR_NUM(6063, SYS_semop)]	 = MAKE_UINT16(3, 471),
	[SYSCALL_OR_NUM(6064, SYS_semctl)]	 = MAKE_UINT16(4, 477),
	[SYSCALL_OR_NUM(6065, SYS_shmdt)]	 = MAKE_UINT16(1, 484),
	[SYSCALL_OR_NUM(6066, SYS_msgget)]	 = MAKE_UINT16(2, 490),
	[SYSCALL_OR_NUM(6067, SYS_msgsnd)]	 = MAKE_UINT16(4, 497),
	[SYSCALL_OR_NUM(6068, SYS_msgrcv)]	 = MAKE_UINT16(5, 504),
	[SYSCALL_OR_NUM(6069, SYS_msgctl)]	 = MAKE_UINT16(3, 511),
	[SYSCALL_OR_NUM(6070, SYS_fcntl)]	 = MAKE_UINT16(3, 518),
	[SYSCALL_OR_NUM(6071, SYS_flock)]	 = MAKE_UINT16(2, 524),
	[SYSCALL_OR_NUM(6072, SYS_fsync)]	 = MAKE_UINT16(1, 530),
	[SYSCALL_OR_NUM(6073, SYS_fdatasync)]	 = MAKE_UINT16(1, 536),
	[SYSCALL_OR_NUM(6074, SYS_truncate)]	 = MAKE_UINT16(2, 546),
	[SYSCALL_OR_NUM(6075, SYS_ftruncate)]	 = MAKE_UINT16(2, 555),
	[SYSCALL_OR_NUM(6076, SYS_getdents)]	 = MAKE_UINT16(3, 565),
	[SYSCALL_OR_NUM(6077, SYS_getcwd)]	 = MAKE_UINT16(2, 574),
	[SYSCALL_OR_NUM(6078, SYS_chdir)]	 = MAKE_UINT16(1, 581),
	[SYSCALL_OR_NUM(6079, SYS_fchdir)]	 = MAKE_UINT16(1, 587),
	[SYSCALL_OR_NUM(6080, SYS_rename)]	 = MAKE_UINT16(2, 594),
	[SYSCALL_OR_NUM(6081, SYS_mkdir)]	 = MAKE_UINT16(2, 601),
	[SYSCALL_OR_NUM(6082, SYS_rmdir)]	 = MAKE_UINT16(1, 607),
	[SYSCALL_OR_NUM(6083, SYS_creat)]	 = MAKE_UINT16(2, 613),
	[SYSCALL_OR_NUM(6084, SYS_link)]	 = MAKE_UINT16(2, 619),
	[SYSCALL_OR_NUM(6085, SYS_unlink)]	 = MAKE_UINT16(1, 624),
	[SYSCALL_OR_NUM(6086, SYS_symlink)]	 = MAKE_UINT16(2, 631),
	[SYSCALL_OR_NUM(6087, SYS_readlink)]	 = MAKE_UINT16(3, 639),
	[SYSCALL_OR_NUM(6088, SYS_chmod)]	 = MAKE_UINT16(2, 648),
	[SYSCALL_OR_NUM(6089, SYS_fchmod)]	 = MAKE_UINT16(2, 654),
	[SYSCALL_OR_NUM(6090, SYS_chown)]	 = MAKE_UINT16(3, 661),
	[SYSCALL_OR_NUM(6091, SYS_fchown)]	 = MAKE_UINT16(3, 667),
	[SYSCALL_OR_NUM(6092, SYS_lchown)]	 = MAKE_UINT16(3, 674),
	[SYSCALL_OR_NUM(6093, SYS_umask)]	 = MAKE_UINT16(1, 681),
	[SYSCALL_OR_NUM(6094, SYS_gettimeofday)]	 = MAKE_UINT16(2, 687),
	[SYSCALL_OR_NUM(6095, SYS_getrlimit)]	 = MAKE_UINT16(2, 700),
	[SYSCALL_OR_NUM(6096, SYS_getrusage)]	 = MAKE_UINT16(2, 710),
	[SYSCALL_OR_NUM(6097, SYS_sysinfo)]	 = MAKE_UINT16(1, 720),
	[SYSCALL_OR_NUM(6098, SYS_times)]	 = MAKE_UINT16(1, 728),
	[SYSCALL_OR_NUM(6099, SYS_ptrace)]	 = MAKE_UINT16(4, 734),
	[SYSCALL_OR_NUM(6100, SYS_getuid)]	 = MAKE_UINT16(0, 741),
	[SYSCALL_OR_NUM(6101, SYS_syslog)]	 = MAKE_UINT16(3, 748),
	[SYSCALL_OR_NUM(6102, SYS_getgid)]	 = MAKE_UINT16(0, 755),
	[SYSCALL_OR_NUM(6103, SYS_setuid)]	 = MAKE_UINT16(1, 762),
	[SYSCALL_OR_NUM(6104, SYS_setgid)]	 = MAKE_UINT16(1, 769),
	[SYSCALL_OR_NUM(6105, SYS_geteuid)]	 = MAKE_UINT16(0, 776),
	[SYSCALL_OR_NUM(6106, SYS_getegid)]	 = MAKE_UINT16(0, 784),
	[SYSCALL_OR_NUM(6107, SYS_setpgid)]	 = MAKE_UINT16(2, 792),
	[SYSCALL_OR_NUM(6108, SYS_getppid)]	 = MAKE_UINT16(0, 800),
	[SYSCALL_OR_NUM(6109, SYS_getpgrp)]	 = MAKE_UINT16(0, 808),
	[SYSCALL_OR_NUM(6110, SYS_setsid)]	 = MAKE_UINT16(0, 816),
	[SYSCALL_OR_NUM(6111, SYS_setreuid)]	 = MAKE_UINT16(2, 823),
	[SYSCALL_OR_NUM(6112, SYS_setregid)]	 = MAKE_UINT16(2, 832),
	[SYSCALL_OR_NUM(6113, SYS_getgroups)]	 = MAKE_UINT16(2, 841),
	[SYSCALL_OR_NUM(6114, SYS_setgroups)]	 = MAKE_UINT16(2, 851),
	[SYSCALL_OR_NUM(6115, SYS_setresuid)]	 = MAKE_UINT16(3, 861),
	[SYSCALL_OR_NUM(6116, SYS_getresuid)]	 = MAKE_UINT16(3, 871),
	[SYSCALL_OR_NUM(6117, SYS_setresgid)]	 = MAKE_UINT16(3, 881),
	[SYSCALL_OR_NUM(6118, SYS_getresgid)]	 = MAKE_UINT16(3, 891),
	[SYSCALL_OR_NUM(6119, SYS_getpgid)]	 = MAKE_UINT16(0, 901),
	[SYSCALL_OR_NUM(6120, SYS_setfsuid)]	 = MAKE_UINT16(1, 909),
	[SYSCALL_OR_NUM(6121, SYS_setfsgid)]	 = MAKE_UINT16(1, 918),
	[SYSCALL_OR_NUM(6122, SYS_getsid)]	 = MAKE_UINT16(1, 927),
	[SYSCALL_OR_NUM(6123, SYS_capget)]	 = MAKE_UINT16(2, 934),
	[SYSCALL_OR_NUM(6124, SYS_capset)]	 = MAKE_UINT16(2, 941),
	[SYSCALL_OR_NUM(6125, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 948),
	[SYSCALL_OR_NUM(6126, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 962),
	[SYSCALL_OR_NUM(6127, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 978),
	[SYSCALL_OR_NUM(6128, SYS_rt_siguspend)]	 = MAKE_UINT16(2, 994),
	[SYSCALL_OR_NUM(6129, SYS_sigaltstatck)]	 = MAKE_UINT16(2, 1007),
	[SYSCALL_OR_NUM(6130, SYS_utime)]	 = MAKE_UINT16(2, 1020),
	[SYSCALL_OR_NUM(6131, SYS_mknod)]	 = MAKE_UINT16(3, 1026),
	[SYSCALL_OR_NUM(6132, SYS_personality)]	 = MAKE_UINT16(1, 1032),
	[SYSCALL_OR_NUM(6133, SYS_ustat)]	 = MAKE_UINT16(2, 1044),
	[SYSCALL_OR_NUM(6134, SYS_statfs)]	 = MAKE_UINT16(3, 1050),
	[SYSCALL_OR_NUM(6135, SYS_fstatfs)]	 = MAKE_UINT16(3, 1057),
	[SYSCALL_OR_NUM(6136, SYS_sysfs)]	 = MAKE_UINT16(5, 1065),
	[SYSCALL_OR_NUM(6137, SYS_getpriority)]	 = MAKE_UINT16(2, 1071),
	[SYSCALL_OR_NUM(6138, SYS_setpriority)]	 = MAKE_UINT16(3, 1083),
	[SYSCALL_OR_NUM(6139, SYS_sched_setparam)]	 = MAKE_UINT16(2, 1095),
	[SYSCALL_OR_NUM(6140, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1110),
	[SYSCALL_OR_NUM(6141, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1125),
	[SYSCALL_OR_NUM(6142, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1144),
	[SYSCALL_OR_NUM(6143, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1163),
	[SYSCALL_OR_NUM(6144, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1186),
	[SYSCALL_OR_NUM(6145, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1209),
	[SYSCALL_OR_NUM(6146, SYS_mlock)]	 = MAKE_UINT16(2, 1231),
	[SYSCALL_OR_NUM(6147, SYS_munlock)]	 = MAKE_UINT16(2, 1237),
	[SYSCALL_OR_NUM(6148, SYS_mlockall)]	 = MAKE_UINT16(1, 1245),
	[SYSCALL_OR_NUM(6149, SYS_munlockall)]	 = MAKE_UINT16(0, 1254),
	[SYSCALL_OR_NUM(6150, SYS_vhangup)]	 = MAKE_UINT16(0, 1265),
	[SYSCALL_OR_NUM(6151, SYS_pivot_root)]	 = MAKE_UINT16(2, 1273),
	[SYSCALL_OR_NUM(6152, SYS__sysctl)]	 = MAKE_UINT16(1, 1284),
	[SYSCALL_OR_NUM(6153, SYS_prctl)]	 = MAKE_UINT16(5, 1292),
	[SYSCALL_OR_NUM(6154, SYS_adjtimex)]	 = MAKE_UINT16(1, 1298),
	[SYSCALL_OR_NUM(6155, SYS_setrlimit)]	 = MAKE_UINT16(2, 1307),
	[SYSCALL_OR_NUM(6156, SYS_chroot)]	 = MAKE_UINT16(1, 1317),
	[SYSCALL_OR_NUM(6157, SYS_sync)]	 = MAKE_UINT16(0, 1324),
	[SYSCALL_OR_NUM(6158, SYS_acct)]	 = MAKE_UINT16(1, 1329),
	[SYSCALL_OR_NUM(6159, SYS_settimeofday)]	 = MAKE_UINT16(2, 1334),
	[SYSCALL_OR_NUM(6160, SYS_mount)]	 = MAKE_UINT16(5, 1347),
	[SYSCALL_OR_NUM(6161, SYS_umount)]	 = MAKE_UINT16(2, 1353),
	[SYSCALL_OR_NUM(6162, SYS_swapon)]	 = MAKE_UINT16(2, 1360),
	[SYSCALL_OR_NUM(6163, SYS_swapoff)]	 = MAKE_UINT16(1, 1367),
	[SYSCALL_OR_NUM(6164, SYS_reboot)]	 = MAKE_UINT16(4, 1375),
	[SYSCALL_OR_NUM(6165, SYS_sethostname)]	 = MAKE_UINT16(2, 1382),
	[SYSCALL_OR_NUM(6166, SYS_setdomainname)]	 = MAKE_UINT16(2, 1394),
	[SYSCALL_OR_NUM(6167, SYS_create_module)]	 = MAKE_UINT16(2, 1408),
	[SYSCALL_OR_NUM(6168, SYS_init_module)]	 = MAKE_UINT16(4, 1422),
	[SYSCALL_OR_NUM(6169, SYS_delete_module)]	 = MAKE_UINT16(1, 1434),
	[SYSCALL_OR_NUM(6170, SYS_get_kernel_syms)]	 = MAKE_UINT16(1, 1448),
	[SYSCALL_OR_NUM(6171, SYS_query_module)]	 = MAKE_UINT16(5, 1464),
	[SYSCALL_OR_NUM(6172, SYS_quotactl)]	 = MAKE_UINT16(4, 1477),
	[SYSCALL_OR_NUM(6173, SYS_nfsservctl)]	 = MAKE_UINT16(3, 1486),
	[SYSCALL_OR_NUM(6174, SYS_getpmsg)]	 = MAKE_UINT16(5, 1497),
	[SYSCALL_OR_NUM(6175, SYS_putpmsg)]	 = MAKE_UINT16(5, 1505),
	[SYSCALL_OR_NUM(6176, SYS_afs_syscall)]	 = MAKE_UINT16(0, 1513),
	[SYSCALL_OR_NUM(6177, SYS_reserved177)]	 = MAKE_UINT16(0, 1525),
	[SYSCALL_OR_NUM(6178, SYS_gettid)]	 = MAKE_UINT16(0, 1537),
	[SYSCALL_OR_NUM(6179, SYS_readahead)]	 = MAKE_UINT16(3, 1544),
	[SYSCALL_OR_NUM(6180, SYS_setxattr)]	 = MAKE_UINT16(5, 1554),
	[SYSCALL_OR_NUM(6181, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1563),
	[SYSCALL_OR_NUM(6182, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1573),
	[SYSCALL_OR_NUM(6183, SYS_getxattr)]	 = MAKE_UINT16(4, 1583),
	[SYSCALL_OR_NUM(6184, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1592),
	[SYSCALL_OR_NUM(6185, SYS_fgetxattr)]	 = MAKE_UINT16(4, 1602),
	[SYSCALL_OR_NUM(6186, SYS_listxattr)]	 = MAKE_UINT16(3, 1612),
	[SYSCALL_OR_NUM(6187, SYS_llistxattr)]	 = MAKE_UINT16(3, 1622),
	[SYSCALL_OR_NUM(6188, SYS_flistxattr)]	 = MAKE_UINT16(3, 1633),
	[SYSCALL_OR_NUM(6189, SYS_removexattr)]	 = MAKE_UINT16(2, 1644),
	[SYSCALL_OR_NUM(6190, SYS_lremovexattr)]	 = MAKE_UINT16(2, 1656),
	[SYSCALL_OR_NUM(6191, SYS_fremovexattr)]	 = MAKE_UINT16(2, 1669),
	[SYSCALL_OR_NUM(6192, SYS_tkill)]	 = MAKE_UINT16(2, 1682),
	[SYSCALL_OR_NUM(6193, SYS_time)]	 = MAKE_UINT16(1, 1688),
	[SYSCALL_OR_NUM(6194, SYS_futex)]	 = MAKE_UINT16(6, 1693),
	[SYSCALL_OR_NUM(6195, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 1699),
	[SYSCALL_OR_NUM(6196, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 1717),
	[SYSCALL_OR_NUM(6197, SYS_cacheflush)]	 = MAKE_UINT16(3, 1735),
	[SYSCALL_OR_NUM(6198, SYS_cachectl)]	 = MAKE_UINT16(3, 1746),
	[SYSCALL_OR_NUM(6199, SYS_sysmips)]	 = MAKE_UINT16(4, 1755),
	[SYSCALL_OR_NUM(6200, SYS_io_setup)]	 = MAKE_UINT16(2, 1763),
	[SYSCALL_OR_NUM(6201, SYS_io_destroy)]	 = MAKE_UINT16(1, 1772),
	[SYSCALL_OR_NUM(6202, SYS_io_getevents)]	 = MAKE_UINT16(5, 1783),
	[SYSCALL_OR_NUM(6203, SYS_io_submit)]	 = MAKE_UINT16(3, 1796),
	[SYSCALL_OR_NUM(6204, SYS_io_cancel)]	 = MAKE_UINT16(3, 1806),
	[SYSCALL_OR_NUM(6205, SYS_exit_group)]	 = MAKE_UINT16(1, 1816),
	[SYSCALL_OR_NUM(6206, SYS_lookup_dcookie)]	 = MAKE_UINT16(3, 1827),
	[SYSCALL_OR_NUM(6207, SYS_epoll_create)]	 = MAKE_UINT16(1, 1842),
	[SYSCALL_OR_NUM(6208, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 1855),
	[SYSCALL_OR_NUM(6209, SYS_epoll_wait)]	 = MAKE_UINT16(4, 1865),
	[SYSCALL_OR_NUM(6210, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 1876),
	[SYSCALL_OR_NUM(6211, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 1893),
	[SYSCALL_OR_NUM(6212, SYS_fcntl64)]	 = MAKE_UINT16(3, 1906),
	[SYSCALL_OR_NUM(6213, SYS_set_tid_address)]	 = MAKE_UINT16(1, 1914),
	[SYSCALL_OR_NUM(6214, SYS_restart_syscall)]	 = MAKE_UINT16(0, 1930),
	[SYSCALL_OR_NUM(6215, SYS_semtimedop)]	 = MAKE_UINT16(5, 1946),
	[SYSCALL_OR_NUM(6216, SYS_fadvise64)]	 = MAKE_UINT16(5, 1957),
	[SYSCALL_OR_NUM(6217, SYS_statfs64)]	 = MAKE_UINT16(3, 1967),
	[SYSCALL_OR_NUM(6218, SYS_fstatfs64)]	 = MAKE_UINT16(3, 1976),
	[SYSCALL_OR_NUM(6219, SYS_sendfile64)]	 = MAKE_UINT16(4, 1986),
	[SYSCALL_OR_NUM(6220, SYS_timer_create)]	 = MAKE_UINT16(3, 1997),
	[SYSCALL_OR_NUM(6221, SYS_timer_settime)]	 = MAKE_UINT16(4, 2010),
	[SYSCALL_OR_NUM(6222, SYS_timer_gettime)]	 = MAKE_UINT16(2, 2024),
	[SYSCALL_OR_NUM(6223, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2038),
	[SYSCALL_OR_NUM(6224, SYS_timer_delete)]	 = MAKE_UINT16(1, 2055),
	[SYSCALL_OR_NUM(6225, SYS_clock_settime)]	 = MAKE_UINT16(2, 2068),
	[SYSCALL_OR_NUM(6226, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2082),
	[SYSCALL_OR_NUM(6227, SYS_clock_getres)]	 = MAKE_UINT16(2, 2096),
	[SYSCALL_OR_NUM(6228, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2109),
	[SYSCALL_OR_NUM(6229, SYS_tgkill)]	 = MAKE_UINT16(3, 2125),
	[SYSCALL_OR_NUM(6230, SYS_utimes)]	 = MAKE_UINT16(2, 2132),
	[SYSCALL_OR_NUM(6234, SYS_mq_open)]	 = MAKE_UINT16(4, 2139),
	[SYSCALL_OR_NUM(6235, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2147),
	[SYSCALL_OR_NUM(6236, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2157),
	[SYSCALL_OR_NUM(6237, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2170),
	[SYSCALL_OR_NUM(6238, SYS_mq_notify)]	 = MAKE_UINT16(2, 2186),
	[SYSCALL_OR_NUM(6239, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2196),
	[SYSCALL_OR_NUM(6241, SYS_waitid)]	 = MAKE_UINT16(5, 2210),
	[SYSCALL_OR_NUM(6243, SYS_add_key)]	 = MAKE_UINT16(5, 2217),
	[SYSCALL_OR_NUM(6244, SYS_request_key)]	 = MAKE_UINT16(4, 2225),
	[SYSCALL_OR_NUM(6245, SYS_keyctl)]	 = MAKE_UINT16(5, 2237),
	[SYSCALL_OR_NUM(6246, SYS_set_thread_area)]	 = MAKE_UINT16(1, 2244),
	[SYSCALL_OR_NUM(6247, SYS_inotify_init)]	 = MAKE_UINT16(0, 2260),
	[SYSCALL_OR_NUM(6248, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2273),
	[SYSCALL_OR_NUM(6249, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2291),
	[SYSCALL_OR_NUM(6250, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2308),
	[SYSCALL_OR_NUM(6251, SYS_openat)]	 = MAKE_UINT16(4, 2322),
	[SYSCALL_OR_NUM(6252, SYS_mkdirat)]	 = MAKE_UINT16(3, 2329),
	[SYSCALL_OR_NUM(6253, SYS_mknodat)]	 = MAKE_UINT16(4, 2337),
	[SYSCALL_OR_NUM(6254, SYS_fchownat)]	 = MAKE_UINT16(5, 2345),
	[SYSCALL_OR_NUM(6255, SYS_futimesat)]	 = MAKE_UINT16(3, 2354),
	[SYSCALL_OR_NUM(6256, SYS_newfstatat)]	 = MAKE_UINT16(4, 2364),
	[SYSCALL_OR_NUM(6257, SYS_unlinkat)]	 = MAKE_UINT16(3, 2375),
	[SYSCALL_OR_NUM(6258, SYS_renameat)]	 = MAKE_UINT16(4, 2384),
	[SYSCALL_OR_NUM(6259, SYS_linkat)]	 = MAKE_UINT16(5, 2393),
	[SYSCALL_OR_NUM(6260, SYS_symlinkat)]	 = MAKE_UINT16(3, 2400),
	[SYSCALL_OR_NUM(6261, SYS_readlinkat)]	 = MAKE_UINT16(4, 2410),
	[SYSCALL_OR_NUM(6262, SYS_fchmodat)]	 = MAKE_UINT16(3, 2421),
	[SYSCALL_OR_NUM(6263, SYS_faccessat)]	 = MAKE_UINT16(3, 2430),
	[SYSCALL_OR_NUM(6264, SYS_pselect6)]	 = MAKE_UINT16(6, 2440),
	[SYSCALL_OR_NUM(6265, SYS_ppoll)]	 = MAKE_UINT16(5, 2449),
	[SYSCALL_OR_NUM(6266, SYS_unshare)]	 = MAKE_UINT16(1, 2455),
	[SYSCALL_OR_NUM(6267, SYS_splice)]	 = MAKE_UINT16(6, 2463),
	[SYSCALL_OR_NUM(6268, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2470),
	[SYSCALL_OR_NUM(6269, SYS_tee)]	 = MAKE_UINT16(4, 2486),
	[SYSCALL_OR_NUM(6270, SYS_vmsplice)]	 = MAKE_UINT16(4, 2490),
	[SYSCALL_OR_NUM(6271, SYS_move_pages)]	 = MAKE_UINT16(6, 2499),
	[SYSCALL_OR_NUM(6272, SYS_set_robust_list)]	 = MAKE_UINT16(2, 2510),
	[SYSCALL_OR_NUM(6273, SYS_get_robust_list)]	 = MAKE_UINT16(3, 2526),
	[SYSCALL_OR_NUM(6274, SYS_kexec_load)]	 = MAKE_UINT16(4, 2542),
	[SYSCALL_OR_NUM(6275, SYS_getcpu)]	 = MAKE_UINT16(3, 2553),
	[SYSCALL_OR_NUM(6276, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2560),
	[SYSCALL_OR_NUM(6277, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2572),
	[SYSCALL_OR_NUM(6278, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2583),
	[SYSCALL_OR_NUM(6279, SYS_utimensat)]	 = MAKE_UINT16(4, 2594),
	[SYSCALL_OR_NUM(6280, SYS_signalfd)]	 = MAKE_UINT16(3, 2604),
	[SYSCALL_OR_NUM(6282, SYS_eventfd)]	 = MAKE_UINT16(1, 2613),
	[SYSCALL_OR_NUM(6283, SYS_fallocate)]	 = MAKE_UINT16(6, 2621),
	[SYSCALL_OR_NUM(6284, SYS_timerfd_create)]	 = MAKE_UINT16(2, 2631),
	[SYSCALL_OR_NUM(6285, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 2646),
	[SYSCALL_OR_NUM(6286, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 2662),
	[SYSCALL_OR_NUM(6287, SYS_signalfd4)]	 = MAKE_UINT16(4, 2678),
	[SYSCALL_OR_NUM(6288, SYS_eventfd2)]	 = MAKE_UINT16(2, 2688),
	[SYSCALL_OR_NUM(6289, SYS_epoll_create1)]	 = MAKE_UINT16(1, 2697),
	[SYSCALL_OR_NUM(6290, SYS_dup3)]	 = MAKE_UINT16(3, 2711),
	[SYSCALL_OR_NUM(6291, SYS_pipe2)]	 = MAKE_UINT16(2, 2716),
	[SYSCALL_OR_NUM(6292, SYS_inotify_init1)]	 = MAKE_UINT16(1, 2722),
	[SYSCALL_OR_NUM(6293, SYS_preadv)]	 = MAKE_UINT16(5, 2736),
	[SYSCALL_OR_NUM(6294, SYS_pwritev)]	 = MAKE_UINT16(5, 2743),
	[SYSCALL_OR_NUM(6295, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 2751),
	[SYSCALL_OR_NUM(6296, SYS_perf_event_open)]	 = MAKE_UINT16(5, 2769),
	[SYSCALL_OR_NUM(6297, SYS_accept4)]	 = MAKE_UINT16(4, 2785),
	[SYSCALL_OR_NUM(6298, SYS_recvmmsg)]	 = MAKE_UINT16(5, 2793),
	[SYSCALL_OR_NUM(6299, SYS_getdents)]	 = MAKE_UINT16(3, 2802),
	[SYSCALL_OR_NUM(6300, SYS_fanotify_init)]	 = MAKE_UINT16(2, 2811),
	[SYSCALL_OR_NUM(6301, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 2825),
	[SYSCALL_OR_NUM(6302, SYS_prlimit64)]	 = MAKE_UINT16(4, 2839),
	[SYSCALL_OR_NUM(6303, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 2849),
	[SYSCALL_OR_NUM(6304, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 2867),
	[SYSCALL_OR_NUM(6305, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 2885),
	[SYSCALL_OR_NUM(6306, SYS_syncfs)]	 = MAKE_UINT16(1, 2899),
	[SYSCALL_OR_NUM(6307, SYS_sendmmsg)]	 = MAKE_UINT16(4, 2906),
	[SYSCALL_OR_NUM(6308, SYS_setns)]	 = MAKE_UINT16(2, 2915),
	[SYSCALL_OR_NUM(6309, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 2921),
	[SYSCALL_OR_NUM(6310, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 2938),
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
"fcntl64\0"
"set_tid_address\0"
"restart_syscall\0"
"semtimedop\0"
"fadvise64\0"
"statfs64\0"
"fstatfs64\0"
"sendfile64\0"
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
"getdents\0"
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
total concatenated string length: 2955
pointer overhead: 2440
strings + overhead: 5395
total size aligned to max strlen 7015
*/
