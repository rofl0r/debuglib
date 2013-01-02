static const syscalldef syscalldefs[] = {
	[SYSCALL_OR_NUM(0, SYS_read)]	 = MAKE_UINT16(3, 1),
	[SYSCALL_OR_NUM(1, SYS_write)]	 = MAKE_UINT16(3, 6),
	[SYSCALL_OR_NUM(2, SYS_open)]	 = MAKE_UINT16(3, 12),
	[SYSCALL_OR_NUM(3, SYS_close)]	 = MAKE_UINT16(1, 17),
	[SYSCALL_OR_NUM(4, SYS_stat)]	 = MAKE_UINT16(2, 23),
	[SYSCALL_OR_NUM(5, SYS_fstat)]	 = MAKE_UINT16(2, 28),
	[SYSCALL_OR_NUM(6, SYS_lstat)]	 = MAKE_UINT16(2, 34),
	[SYSCALL_OR_NUM(7, SYS_poll)]	 = MAKE_UINT16(3, 40),
	[SYSCALL_OR_NUM(8, SYS_lseek)]	 = MAKE_UINT16(3, 45),
	[SYSCALL_OR_NUM(9, SYS_mmap)]	 = MAKE_UINT16(6, 51),
	[SYSCALL_OR_NUM(10, SYS_mprotect)]	 = MAKE_UINT16(3, 56),
	[SYSCALL_OR_NUM(11, SYS_munmap)]	 = MAKE_UINT16(2, 65),
	[SYSCALL_OR_NUM(12, SYS_brk)]	 = MAKE_UINT16(1, 72),
	[SYSCALL_OR_NUM(13, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 76),
	[SYSCALL_OR_NUM(14, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 89),
	[SYSCALL_OR_NUM(15, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 104),
	[SYSCALL_OR_NUM(16, SYS_ioctl)]	 = MAKE_UINT16(3, 117),
	[SYSCALL_OR_NUM(17, SYS_pread)]	 = MAKE_UINT16(5, 123),
	[SYSCALL_OR_NUM(18, SYS_pwrite)]	 = MAKE_UINT16(5, 129),
	[SYSCALL_OR_NUM(19, SYS_readv)]	 = MAKE_UINT16(3, 136),
	[SYSCALL_OR_NUM(20, SYS_writev)]	 = MAKE_UINT16(3, 142),
	[SYSCALL_OR_NUM(21, SYS_access)]	 = MAKE_UINT16(2, 149),
	[SYSCALL_OR_NUM(22, SYS_pipe)]	 = MAKE_UINT16(1, 156),
	[SYSCALL_OR_NUM(23, SYS_select)]	 = MAKE_UINT16(5, 161),
	[SYSCALL_OR_NUM(24, SYS_sched_yield)]	 = MAKE_UINT16(0, 168),
	[SYSCALL_OR_NUM(25, SYS_mremap)]	 = MAKE_UINT16(5, 180),
	[SYSCALL_OR_NUM(26, SYS_msync)]	 = MAKE_UINT16(3, 187),
	[SYSCALL_OR_NUM(27, SYS_mincore)]	 = MAKE_UINT16(3, 193),
	[SYSCALL_OR_NUM(28, SYS_madvise)]	 = MAKE_UINT16(3, 201),
	[SYSCALL_OR_NUM(29, SYS_shmget)]	 = MAKE_UINT16(4, 209),
	[SYSCALL_OR_NUM(30, SYS_shmat)]	 = MAKE_UINT16(4, 216),
	[SYSCALL_OR_NUM(31, SYS_shmctl)]	 = MAKE_UINT16(4, 222),
	[SYSCALL_OR_NUM(32, SYS_dup)]	 = MAKE_UINT16(1, 229),
	[SYSCALL_OR_NUM(33, SYS_dup2)]	 = MAKE_UINT16(2, 233),
	[SYSCALL_OR_NUM(34, SYS_pause)]	 = MAKE_UINT16(0, 238),
	[SYSCALL_OR_NUM(35, SYS_nanosleep)]	 = MAKE_UINT16(2, 244),
	[SYSCALL_OR_NUM(36, SYS_getitimer)]	 = MAKE_UINT16(2, 254),
	[SYSCALL_OR_NUM(37, SYS_alarm)]	 = MAKE_UINT16(1, 264),
	[SYSCALL_OR_NUM(38, SYS_setitimer)]	 = MAKE_UINT16(3, 270),
	[SYSCALL_OR_NUM(39, SYS_getpid)]	 = MAKE_UINT16(0, 280),
	[SYSCALL_OR_NUM(40, SYS_sendfile)]	 = MAKE_UINT16(4, 287),
	[SYSCALL_OR_NUM(41, SYS_socket)]	 = MAKE_UINT16(3, 296),
	[SYSCALL_OR_NUM(42, SYS_connect)]	 = MAKE_UINT16(3, 303),
	[SYSCALL_OR_NUM(43, SYS_accept)]	 = MAKE_UINT16(3, 311),
	[SYSCALL_OR_NUM(44, SYS_sendto)]	 = MAKE_UINT16(6, 318),
	[SYSCALL_OR_NUM(45, SYS_recvfrom)]	 = MAKE_UINT16(6, 325),
	[SYSCALL_OR_NUM(46, SYS_sendmsg)]	 = MAKE_UINT16(3, 334),
	[SYSCALL_OR_NUM(47, SYS_recvmsg)]	 = MAKE_UINT16(5, 342),
	[SYSCALL_OR_NUM(48, SYS_shutdown)]	 = MAKE_UINT16(2, 350),
	[SYSCALL_OR_NUM(49, SYS_bind)]	 = MAKE_UINT16(3, 359),
	[SYSCALL_OR_NUM(50, SYS_listen)]	 = MAKE_UINT16(2, 364),
	[SYSCALL_OR_NUM(51, SYS_getsockname)]	 = MAKE_UINT16(3, 371),
	[SYSCALL_OR_NUM(52, SYS_getpeername)]	 = MAKE_UINT16(3, 383),
	[SYSCALL_OR_NUM(53, SYS_socketpair)]	 = MAKE_UINT16(4, 395),
	[SYSCALL_OR_NUM(54, SYS_setsockopt)]	 = MAKE_UINT16(5, 406),
	[SYSCALL_OR_NUM(55, SYS_getsockopt)]	 = MAKE_UINT16(5, 417),
	[SYSCALL_OR_NUM(56, SYS_clone)]	 = MAKE_UINT16(5, 428),
	[SYSCALL_OR_NUM(57, SYS_fork)]	 = MAKE_UINT16(0, 434),
	[SYSCALL_OR_NUM(58, SYS_vfork)]	 = MAKE_UINT16(0, 439),
	[SYSCALL_OR_NUM(59, SYS_execve)]	 = MAKE_UINT16(3, 445),
	[SYSCALL_OR_NUM(60, SYS__exit)]	 = MAKE_UINT16(1, 452),
	[SYSCALL_OR_NUM(61, SYS_wait4)]	 = MAKE_UINT16(4, 458),
	[SYSCALL_OR_NUM(62, SYS_kill)]	 = MAKE_UINT16(2, 464),
	[SYSCALL_OR_NUM(63, SYS_uname)]	 = MAKE_UINT16(1, 469),
	[SYSCALL_OR_NUM(64, SYS_semget)]	 = MAKE_UINT16(4, 475),
	[SYSCALL_OR_NUM(65, SYS_semop)]	 = MAKE_UINT16(4, 482),
	[SYSCALL_OR_NUM(66, SYS_semctl)]	 = MAKE_UINT16(4, 488),
	[SYSCALL_OR_NUM(67, SYS_shmdt)]	 = MAKE_UINT16(4, 495),
	[SYSCALL_OR_NUM(68, SYS_msgget)]	 = MAKE_UINT16(4, 501),
	[SYSCALL_OR_NUM(69, SYS_msgsnd)]	 = MAKE_UINT16(4, 508),
	[SYSCALL_OR_NUM(70, SYS_msgrcv)]	 = MAKE_UINT16(5, 515),
	[SYSCALL_OR_NUM(71, SYS_msgctl)]	 = MAKE_UINT16(3, 522),
	[SYSCALL_OR_NUM(72, SYS_fcntl)]	 = MAKE_UINT16(3, 529),
	[SYSCALL_OR_NUM(73, SYS_flock)]	 = MAKE_UINT16(2, 535),
	[SYSCALL_OR_NUM(74, SYS_fsync)]	 = MAKE_UINT16(1, 541),
	[SYSCALL_OR_NUM(75, SYS_fdatasync)]	 = MAKE_UINT16(1, 547),
	[SYSCALL_OR_NUM(76, SYS_truncate)]	 = MAKE_UINT16(2, 557),
	[SYSCALL_OR_NUM(77, SYS_ftruncate)]	 = MAKE_UINT16(2, 566),
	[SYSCALL_OR_NUM(78, SYS_getdents)]	 = MAKE_UINT16(3, 576),
	[SYSCALL_OR_NUM(79, SYS_getcwd)]	 = MAKE_UINT16(2, 585),
	[SYSCALL_OR_NUM(80, SYS_chdir)]	 = MAKE_UINT16(1, 592),
	[SYSCALL_OR_NUM(81, SYS_fchdir)]	 = MAKE_UINT16(1, 598),
	[SYSCALL_OR_NUM(82, SYS_rename)]	 = MAKE_UINT16(2, 605),
	[SYSCALL_OR_NUM(83, SYS_mkdir)]	 = MAKE_UINT16(2, 612),
	[SYSCALL_OR_NUM(84, SYS_rmdir)]	 = MAKE_UINT16(1, 618),
	[SYSCALL_OR_NUM(85, SYS_creat)]	 = MAKE_UINT16(2, 624),
	[SYSCALL_OR_NUM(86, SYS_link)]	 = MAKE_UINT16(2, 630),
	[SYSCALL_OR_NUM(87, SYS_unlink)]	 = MAKE_UINT16(1, 635),
	[SYSCALL_OR_NUM(88, SYS_symlink)]	 = MAKE_UINT16(2, 642),
	[SYSCALL_OR_NUM(89, SYS_readlink)]	 = MAKE_UINT16(3, 650),
	[SYSCALL_OR_NUM(90, SYS_chmod)]	 = MAKE_UINT16(2, 659),
	[SYSCALL_OR_NUM(91, SYS_fchmod)]	 = MAKE_UINT16(2, 665),
	[SYSCALL_OR_NUM(92, SYS_chown)]	 = MAKE_UINT16(3, 672),
	[SYSCALL_OR_NUM(93, SYS_fchown)]	 = MAKE_UINT16(3, 678),
	[SYSCALL_OR_NUM(94, SYS_lchown)]	 = MAKE_UINT16(3, 685),
	[SYSCALL_OR_NUM(95, SYS_umask)]	 = MAKE_UINT16(1, 692),
	[SYSCALL_OR_NUM(96, SYS_gettimeofday)]	 = MAKE_UINT16(2, 698),
	[SYSCALL_OR_NUM(97, SYS_getrlimit)]	 = MAKE_UINT16(2, 711),
	[SYSCALL_OR_NUM(98, SYS_getrusage)]	 = MAKE_UINT16(2, 721),
	[SYSCALL_OR_NUM(99, SYS_sysinfo)]	 = MAKE_UINT16(1, 731),
	[SYSCALL_OR_NUM(100, SYS_times)]	 = MAKE_UINT16(1, 739),
	[SYSCALL_OR_NUM(101, SYS_ptrace)]	 = MAKE_UINT16(4, 745),
	[SYSCALL_OR_NUM(102, SYS_getuid)]	 = MAKE_UINT16(0, 752),
	[SYSCALL_OR_NUM(103, SYS_syslog)]	 = MAKE_UINT16(3, 759),
	[SYSCALL_OR_NUM(104, SYS_getgid)]	 = MAKE_UINT16(0, 766),
	[SYSCALL_OR_NUM(105, SYS_setuid)]	 = MAKE_UINT16(1, 773),
	[SYSCALL_OR_NUM(106, SYS_setgid)]	 = MAKE_UINT16(1, 780),
	[SYSCALL_OR_NUM(107, SYS_geteuid)]	 = MAKE_UINT16(0, 787),
	[SYSCALL_OR_NUM(108, SYS_getegid)]	 = MAKE_UINT16(0, 795),
	[SYSCALL_OR_NUM(109, SYS_setpgid)]	 = MAKE_UINT16(2, 803),
	[SYSCALL_OR_NUM(110, SYS_getppid)]	 = MAKE_UINT16(0, 811),
	[SYSCALL_OR_NUM(111, SYS_getpgrp)]	 = MAKE_UINT16(0, 819),
	[SYSCALL_OR_NUM(112, SYS_setsid)]	 = MAKE_UINT16(0, 827),
	[SYSCALL_OR_NUM(113, SYS_setreuid)]	 = MAKE_UINT16(2, 834),
	[SYSCALL_OR_NUM(114, SYS_setregid)]	 = MAKE_UINT16(2, 843),
	[SYSCALL_OR_NUM(115, SYS_getgroups)]	 = MAKE_UINT16(2, 852),
	[SYSCALL_OR_NUM(116, SYS_setgroups)]	 = MAKE_UINT16(2, 862),
	[SYSCALL_OR_NUM(117, SYS_setresuid)]	 = MAKE_UINT16(3, 872),
	[SYSCALL_OR_NUM(118, SYS_getresuid)]	 = MAKE_UINT16(3, 882),
	[SYSCALL_OR_NUM(119, SYS_setresgid)]	 = MAKE_UINT16(3, 892),
	[SYSCALL_OR_NUM(120, SYS_getresgid)]	 = MAKE_UINT16(3, 902),
	[SYSCALL_OR_NUM(121, SYS_getpgid)]	 = MAKE_UINT16(1, 912),
	[SYSCALL_OR_NUM(122, SYS_setfsuid)]	 = MAKE_UINT16(1, 920),
	[SYSCALL_OR_NUM(123, SYS_setfsgid)]	 = MAKE_UINT16(1, 929),
	[SYSCALL_OR_NUM(124, SYS_getsid)]	 = MAKE_UINT16(1, 938),
	[SYSCALL_OR_NUM(125, SYS_capget)]	 = MAKE_UINT16(2, 945),
	[SYSCALL_OR_NUM(126, SYS_capset)]	 = MAKE_UINT16(2, 952),
	[SYSCALL_OR_NUM(127, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 959),
	[SYSCALL_OR_NUM(128, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 973),
	[SYSCALL_OR_NUM(129, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 989),
	[SYSCALL_OR_NUM(130, SYS_rt_sigsuspend)]	 = MAKE_UINT16(2, 1005),
	[SYSCALL_OR_NUM(131, SYS_sigaltstack)]	 = MAKE_UINT16(2, 1019),
	[SYSCALL_OR_NUM(132, SYS_utime)]	 = MAKE_UINT16(2, 1031),
	[SYSCALL_OR_NUM(133, SYS_mknod)]	 = MAKE_UINT16(3, 1037),
	[SYSCALL_OR_NUM(134, SYS_uselib)]	 = MAKE_UINT16(1, 1043),
	[SYSCALL_OR_NUM(135, SYS_personality)]	 = MAKE_UINT16(1, 1050),
	[SYSCALL_OR_NUM(136, SYS_ustat)]	 = MAKE_UINT16(2, 1062),
	[SYSCALL_OR_NUM(137, SYS_statfs)]	 = MAKE_UINT16(2, 1068),
	[SYSCALL_OR_NUM(138, SYS_fstatfs)]	 = MAKE_UINT16(2, 1075),
	[SYSCALL_OR_NUM(139, SYS_sysfs)]	 = MAKE_UINT16(3, 1083),
	[SYSCALL_OR_NUM(140, SYS_getpriority)]	 = MAKE_UINT16(2, 1089),
	[SYSCALL_OR_NUM(141, SYS_setpriority)]	 = MAKE_UINT16(3, 1101),
	[SYSCALL_OR_NUM(142, SYS_sched_setparam)]	 = MAKE_UINT16(0, 1113),
	[SYSCALL_OR_NUM(143, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1128),
	[SYSCALL_OR_NUM(144, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1143),
	[SYSCALL_OR_NUM(145, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1162),
	[SYSCALL_OR_NUM(146, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1181),
	[SYSCALL_OR_NUM(147, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1204),
	[SYSCALL_OR_NUM(148, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1227),
	[SYSCALL_OR_NUM(149, SYS_mlock)]	 = MAKE_UINT16(2, 1249),
	[SYSCALL_OR_NUM(150, SYS_munlock)]	 = MAKE_UINT16(2, 1255),
	[SYSCALL_OR_NUM(151, SYS_mlockall)]	 = MAKE_UINT16(1, 1263),
	[SYSCALL_OR_NUM(152, SYS_munlockall)]	 = MAKE_UINT16(0, 1272),
	[SYSCALL_OR_NUM(153, SYS_vhangup)]	 = MAKE_UINT16(0, 1283),
	[SYSCALL_OR_NUM(154, SYS_modify_ldt)]	 = MAKE_UINT16(3, 1291),
	[SYSCALL_OR_NUM(155, SYS_pivot_root)]	 = MAKE_UINT16(2, 1302),
	[SYSCALL_OR_NUM(156, SYS__sysctl)]	 = MAKE_UINT16(1, 1313),
	[SYSCALL_OR_NUM(157, SYS_prctl)]	 = MAKE_UINT16(5, 1321),
	[SYSCALL_OR_NUM(158, SYS_arch_prctl)]	 = MAKE_UINT16(2, 1327),
	[SYSCALL_OR_NUM(159, SYS_adjtimex)]	 = MAKE_UINT16(1, 1338),
	[SYSCALL_OR_NUM(160, SYS_setrlimit)]	 = MAKE_UINT16(2, 1347),
	[SYSCALL_OR_NUM(161, SYS_chroot)]	 = MAKE_UINT16(1, 1357),
	[SYSCALL_OR_NUM(162, SYS_sync)]	 = MAKE_UINT16(0, 1364),
	[SYSCALL_OR_NUM(163, SYS_acct)]	 = MAKE_UINT16(1, 1369),
	[SYSCALL_OR_NUM(164, SYS_settimeofday)]	 = MAKE_UINT16(2, 1374),
	[SYSCALL_OR_NUM(165, SYS_mount)]	 = MAKE_UINT16(5, 1387),
	[SYSCALL_OR_NUM(166, SYS_umount)]	 = MAKE_UINT16(2, 1393),
	[SYSCALL_OR_NUM(167, SYS_swapon)]	 = MAKE_UINT16(2, 1400),
	[SYSCALL_OR_NUM(168, SYS_swapoff)]	 = MAKE_UINT16(1, 1407),
	[SYSCALL_OR_NUM(169, SYS_reboot)]	 = MAKE_UINT16(4, 1415),
	[SYSCALL_OR_NUM(170, SYS_sethostname)]	 = MAKE_UINT16(2, 1422),
	[SYSCALL_OR_NUM(171, SYS_setdomainname)]	 = MAKE_UINT16(2, 1434),
	[SYSCALL_OR_NUM(172, SYS_iopl)]	 = MAKE_UINT16(1, 1448),
	[SYSCALL_OR_NUM(173, SYS_ioperm)]	 = MAKE_UINT16(3, 1453),
	[SYSCALL_OR_NUM(174, SYS_create_module)]	 = MAKE_UINT16(2, 1460),
	[SYSCALL_OR_NUM(175, SYS_init_module)]	 = MAKE_UINT16(3, 1474),
	[SYSCALL_OR_NUM(176, SYS_delete_module)]	 = MAKE_UINT16(2, 1486),
	[SYSCALL_OR_NUM(177, SYS_get_kernel_syms)]	 = MAKE_UINT16(1, 1500),
	[SYSCALL_OR_NUM(178, SYS_query_module)]	 = MAKE_UINT16(5, 1516),
	[SYSCALL_OR_NUM(179, SYS_quotactl)]	 = MAKE_UINT16(4, 1529),
	[SYSCALL_OR_NUM(180, SYS_nfsservctl)]	 = MAKE_UINT16(3, 1538),
	[SYSCALL_OR_NUM(181, SYS_getpmsg)]	 = MAKE_UINT16(5, 1549),
	[SYSCALL_OR_NUM(182, SYS_putpmsg)]	 = MAKE_UINT16(5, 1557),
	[SYSCALL_OR_NUM(183, SYS_afs_syscall)]	 = MAKE_UINT16(5, 1565),
	[SYSCALL_OR_NUM(184, SYS_tuxcall)]	 = MAKE_UINT16(3, 1577),
	[SYSCALL_OR_NUM(185, SYS_security)]	 = MAKE_UINT16(3, 1585),
	[SYSCALL_OR_NUM(186, SYS_gettid)]	 = MAKE_UINT16(0, 1594),
	[SYSCALL_OR_NUM(187, SYS_readahead)]	 = MAKE_UINT16(4, 1601),
	[SYSCALL_OR_NUM(188, SYS_setxattr)]	 = MAKE_UINT16(5, 1611),
	[SYSCALL_OR_NUM(189, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1620),
	[SYSCALL_OR_NUM(190, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1630),
	[SYSCALL_OR_NUM(191, SYS_getxattr)]	 = MAKE_UINT16(4, 1640),
	[SYSCALL_OR_NUM(192, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1649),
	[SYSCALL_OR_NUM(193, SYS_fgetxattr)]	 = MAKE_UINT16(4, 1659),
	[SYSCALL_OR_NUM(194, SYS_listxattr)]	 = MAKE_UINT16(3, 1669),
	[SYSCALL_OR_NUM(195, SYS_llistxattr)]	 = MAKE_UINT16(3, 1679),
	[SYSCALL_OR_NUM(196, SYS_flistxattr)]	 = MAKE_UINT16(3, 1690),
	[SYSCALL_OR_NUM(197, SYS_removexattr)]	 = MAKE_UINT16(2, 1701),
	[SYSCALL_OR_NUM(198, SYS_lremovexattr)]	 = MAKE_UINT16(2, 1713),
	[SYSCALL_OR_NUM(199, SYS_fremovexattr)]	 = MAKE_UINT16(2, 1726),
	[SYSCALL_OR_NUM(200, SYS_tkill)]	 = MAKE_UINT16(2, 1739),
	[SYSCALL_OR_NUM(201, SYS_time)]	 = MAKE_UINT16(1, 1745),
	[SYSCALL_OR_NUM(202, SYS_futex)]	 = MAKE_UINT16(6, 1750),
	[SYSCALL_OR_NUM(203, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 1756),
	[SYSCALL_OR_NUM(204, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 1774),
	[SYSCALL_OR_NUM(205, SYS_set_thread_area)]	 = MAKE_UINT16(1, 1792),
	[SYSCALL_OR_NUM(206, SYS_io_setup)]	 = MAKE_UINT16(2, 1808),
	[SYSCALL_OR_NUM(207, SYS_io_destroy)]	 = MAKE_UINT16(1, 1817),
	[SYSCALL_OR_NUM(208, SYS_io_getevents)]	 = MAKE_UINT16(5, 1828),
	[SYSCALL_OR_NUM(209, SYS_io_submit)]	 = MAKE_UINT16(3, 1841),
	[SYSCALL_OR_NUM(210, SYS_io_cancel)]	 = MAKE_UINT16(3, 1851),
	[SYSCALL_OR_NUM(211, SYS_get_thread_area)]	 = MAKE_UINT16(1, 1861),
	[SYSCALL_OR_NUM(212, SYS_lookup_dcookie)]	 = MAKE_UINT16(4, 1877),
	[SYSCALL_OR_NUM(213, SYS_epoll_create)]	 = MAKE_UINT16(1, 1892),
	[SYSCALL_OR_NUM(214, SYS_epoll_ctl_old)]	 = MAKE_UINT16(4, 1905),
	[SYSCALL_OR_NUM(215, SYS_epoll_wait_old)]	 = MAKE_UINT16(4, 1919),
	[SYSCALL_OR_NUM(216, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 1934),
	[SYSCALL_OR_NUM(217, SYS_getdents64)]	 = MAKE_UINT16(3, 1951),
	[SYSCALL_OR_NUM(218, SYS_set_tid_address)]	 = MAKE_UINT16(1, 1962),
	[SYSCALL_OR_NUM(219, SYS_restart_syscall)]	 = MAKE_UINT16(0, 1978),
	[SYSCALL_OR_NUM(220, SYS_semtimedop)]	 = MAKE_UINT16(5, 1994),
	[SYSCALL_OR_NUM(221, SYS_fadvise64)]	 = MAKE_UINT16(4, 2005),
	[SYSCALL_OR_NUM(222, SYS_timer_create)]	 = MAKE_UINT16(3, 2015),
	[SYSCALL_OR_NUM(223, SYS_timer_settime)]	 = MAKE_UINT16(4, 2028),
	[SYSCALL_OR_NUM(224, SYS_timer_gettime)]	 = MAKE_UINT16(2, 2042),
	[SYSCALL_OR_NUM(225, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2056),
	[SYSCALL_OR_NUM(226, SYS_timer_delete)]	 = MAKE_UINT16(1, 2073),
	[SYSCALL_OR_NUM(227, SYS_clock_settime)]	 = MAKE_UINT16(2, 2086),
	[SYSCALL_OR_NUM(228, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2100),
	[SYSCALL_OR_NUM(229, SYS_clock_getres)]	 = MAKE_UINT16(2, 2114),
	[SYSCALL_OR_NUM(230, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2127),
	[SYSCALL_OR_NUM(231, SYS_exit_group)]	 = MAKE_UINT16(1, 2143),
	[SYSCALL_OR_NUM(232, SYS_epoll_wait)]	 = MAKE_UINT16(4, 2154),
	[SYSCALL_OR_NUM(233, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 2165),
	[SYSCALL_OR_NUM(234, SYS_tgkill)]	 = MAKE_UINT16(3, 2175),
	[SYSCALL_OR_NUM(235, SYS_utimes)]	 = MAKE_UINT16(2, 2182),
	[SYSCALL_OR_NUM(236, SYS_vserver)]	 = MAKE_UINT16(5, 2189),
	[SYSCALL_OR_NUM(237, SYS_mbind)]	 = MAKE_UINT16(6, 2197),
	[SYSCALL_OR_NUM(238, SYS_set_mempolicy)]	 = MAKE_UINT16(3, 2203),
	[SYSCALL_OR_NUM(239, SYS_get_mempolicy)]	 = MAKE_UINT16(5, 2217),
	[SYSCALL_OR_NUM(240, SYS_mq_open)]	 = MAKE_UINT16(4, 2231),
	[SYSCALL_OR_NUM(241, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2239),
	[SYSCALL_OR_NUM(242, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2249),
	[SYSCALL_OR_NUM(243, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2262),
	[SYSCALL_OR_NUM(244, SYS_mq_notify)]	 = MAKE_UINT16(2, 2278),
	[SYSCALL_OR_NUM(245, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2288),
	[SYSCALL_OR_NUM(246, SYS_kexec_load)]	 = MAKE_UINT16(4, 2302),
	[SYSCALL_OR_NUM(247, SYS_waitid)]	 = MAKE_UINT16(5, 2313),
	[SYSCALL_OR_NUM(248, SYS_add_key)]	 = MAKE_UINT16(5, 2320),
	[SYSCALL_OR_NUM(249, SYS_request_key)]	 = MAKE_UINT16(4, 2328),
	[SYSCALL_OR_NUM(250, SYS_keyctl)]	 = MAKE_UINT16(5, 2340),
	[SYSCALL_OR_NUM(251, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2347),
	[SYSCALL_OR_NUM(252, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2358),
	[SYSCALL_OR_NUM(253, SYS_inotify_init)]	 = MAKE_UINT16(0, 2369),
	[SYSCALL_OR_NUM(254, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2382),
	[SYSCALL_OR_NUM(255, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2400),
	[SYSCALL_OR_NUM(256, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2417),
	[SYSCALL_OR_NUM(257, SYS_openat)]	 = MAKE_UINT16(4, 2431),
	[SYSCALL_OR_NUM(258, SYS_mkdirat)]	 = MAKE_UINT16(3, 2438),
	[SYSCALL_OR_NUM(259, SYS_mknodat)]	 = MAKE_UINT16(4, 2446),
	[SYSCALL_OR_NUM(260, SYS_fchownat)]	 = MAKE_UINT16(5, 2454),
	[SYSCALL_OR_NUM(261, SYS_futimesat)]	 = MAKE_UINT16(3, 2463),
	[SYSCALL_OR_NUM(262, SYS_newfstatat)]	 = MAKE_UINT16(4, 2473),
	[SYSCALL_OR_NUM(263, SYS_unlinkat)]	 = MAKE_UINT16(3, 2484),
	[SYSCALL_OR_NUM(264, SYS_renameat)]	 = MAKE_UINT16(4, 2493),
	[SYSCALL_OR_NUM(265, SYS_linkat)]	 = MAKE_UINT16(5, 2502),
	[SYSCALL_OR_NUM(266, SYS_symlinkat)]	 = MAKE_UINT16(3, 2509),
	[SYSCALL_OR_NUM(267, SYS_readlinkat)]	 = MAKE_UINT16(4, 2519),
	[SYSCALL_OR_NUM(268, SYS_fchmodat)]	 = MAKE_UINT16(3, 2530),
	[SYSCALL_OR_NUM(269, SYS_faccessat)]	 = MAKE_UINT16(3, 2539),
	[SYSCALL_OR_NUM(270, SYS_pselect6)]	 = MAKE_UINT16(6, 2549),
	[SYSCALL_OR_NUM(271, SYS_ppoll)]	 = MAKE_UINT16(5, 2558),
	[SYSCALL_OR_NUM(272, SYS_unshare)]	 = MAKE_UINT16(1, 2564),
	[SYSCALL_OR_NUM(273, SYS_set_robust_list)]	 = MAKE_UINT16(2, 2572),
	[SYSCALL_OR_NUM(274, SYS_get_robust_list)]	 = MAKE_UINT16(3, 2588),
	[SYSCALL_OR_NUM(275, SYS_splice)]	 = MAKE_UINT16(6, 2604),
	[SYSCALL_OR_NUM(276, SYS_tee)]	 = MAKE_UINT16(4, 2611),
	[SYSCALL_OR_NUM(277, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2615),
	[SYSCALL_OR_NUM(278, SYS_vmsplice)]	 = MAKE_UINT16(4, 2631),
	[SYSCALL_OR_NUM(279, SYS_move_pages)]	 = MAKE_UINT16(6, 2640),
	[SYSCALL_OR_NUM(280, SYS_utimensat)]	 = MAKE_UINT16(4, 2651),
	[SYSCALL_OR_NUM(281, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2661),
	[SYSCALL_OR_NUM(282, SYS_signalfd)]	 = MAKE_UINT16(3, 2673),
	[SYSCALL_OR_NUM(283, SYS_timerfd_create)]	 = MAKE_UINT16(2, 2682),
	[SYSCALL_OR_NUM(284, SYS_eventfd)]	 = MAKE_UINT16(1, 2697),
	[SYSCALL_OR_NUM(285, SYS_fallocate)]	 = MAKE_UINT16(6, 2705),
	[SYSCALL_OR_NUM(286, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 2715),
	[SYSCALL_OR_NUM(287, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 2731),
	[SYSCALL_OR_NUM(288, SYS_accept4)]	 = MAKE_UINT16(4, 2747),
	[SYSCALL_OR_NUM(289, SYS_signalfd4)]	 = MAKE_UINT16(4, 2755),
	[SYSCALL_OR_NUM(290, SYS_eventfd2)]	 = MAKE_UINT16(2, 2765),
	[SYSCALL_OR_NUM(291, SYS_epoll_create1)]	 = MAKE_UINT16(1, 2774),
	[SYSCALL_OR_NUM(292, SYS_dup3)]	 = MAKE_UINT16(3, 2788),
	[SYSCALL_OR_NUM(293, SYS_pipe2)]	 = MAKE_UINT16(2, 2793),
	[SYSCALL_OR_NUM(294, SYS_inotify_init1)]	 = MAKE_UINT16(1, 2799),
	[SYSCALL_OR_NUM(295, SYS_preadv)]	 = MAKE_UINT16(5, 2813),
	[SYSCALL_OR_NUM(296, SYS_pwritev)]	 = MAKE_UINT16(5, 2820),
	[SYSCALL_OR_NUM(297, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 2828),
	[SYSCALL_OR_NUM(298, SYS_perf_event_open)]	 = MAKE_UINT16(5, 2846),
	[SYSCALL_OR_NUM(299, SYS_recvmmsg)]	 = MAKE_UINT16(5, 2862),
	[SYSCALL_OR_NUM(300, SYS_fanotify_init)]	 = MAKE_UINT16(2, 2871),
	[SYSCALL_OR_NUM(301, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 2885),
	[SYSCALL_OR_NUM(302, SYS_prlimit64)]	 = MAKE_UINT16(4, 2899),
	[SYSCALL_OR_NUM(303, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 2909),
	[SYSCALL_OR_NUM(304, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 2927),
	[SYSCALL_OR_NUM(305, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 2945),
	[SYSCALL_OR_NUM(306, SYS_syncfs)]	 = MAKE_UINT16(1, 2959),
	[SYSCALL_OR_NUM(307, SYS_sendmmsg)]	 = MAKE_UINT16(4, 2966),
	[SYSCALL_OR_NUM(308, SYS_setns)]	 = MAKE_UINT16(2, 2975),
	[SYSCALL_OR_NUM(309, SYS_getcpu)]	 = MAKE_UINT16(3, 2981),
	[SYSCALL_OR_NUM(310, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 2988),
	[SYSCALL_OR_NUM(311, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 3005),
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
"rt_sigreturn\0"
"ioctl\0"
"pread\0"
"pwrite\0"
"readv\0"
"writev\0"
"access\0"
"pipe\0"
"select\0"
"sched_yield\0"
"mremap\0"
"msync\0"
"mincore\0"
"madvise\0"
"shmget\0"
"shmat\0"
"shmctl\0"
"dup\0"
"dup2\0"
"pause\0"
"nanosleep\0"
"getitimer\0"
"alarm\0"
"setitimer\0"
"getpid\0"
"sendfile\0"
"socket\0"
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
"vfork\0"
"execve\0"
"_exit\0"
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
"rt_sigsuspend\0"
"sigaltstack\0"
"utime\0"
"mknod\0"
"uselib\0"
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
"modify_ldt\0"
"pivot_root\0"
"_sysctl\0"
"prctl\0"
"arch_prctl\0"
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
"iopl\0"
"ioperm\0"
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
"tuxcall\0"
"security\0"
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
"set_thread_area\0"
"io_setup\0"
"io_destroy\0"
"io_getevents\0"
"io_submit\0"
"io_cancel\0"
"get_thread_area\0"
"lookup_dcookie\0"
"epoll_create\0"
"epoll_ctl_old\0"
"epoll_wait_old\0"
"remap_file_pages\0"
"getdents64\0"
"set_tid_address\0"
"restart_syscall\0"
"semtimedop\0"
"fadvise64\0"
"timer_create\0"
"timer_settime\0"
"timer_gettime\0"
"timer_getoverrun\0"
"timer_delete\0"
"clock_settime\0"
"clock_gettime\0"
"clock_getres\0"
"clock_nanosleep\0"
"exit_group\0"
"epoll_wait\0"
"epoll_ctl\0"
"tgkill\0"
"utimes\0"
"vserver\0"
"mbind\0"
"set_mempolicy\0"
"get_mempolicy\0"
"mq_open\0"
"mq_unlink\0"
"mq_timedsend\0"
"mq_timedreceive\0"
"mq_notify\0"
"mq_getsetattr\0"
"kexec_load\0"
"waitid\0"
"add_key\0"
"request_key\0"
"keyctl\0"
"ioprio_set\0"
"ioprio_get\0"
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
"set_robust_list\0"
"get_robust_list\0"
"splice\0"
"tee\0"
"sync_file_range\0"
"vmsplice\0"
"move_pages\0"
"utimensat\0"
"epoll_pwait\0"
"signalfd\0"
"timerfd_create\0"
"eventfd\0"
"fallocate\0"
"timerfd_settime\0"
"timerfd_gettime\0"
"accept4\0"
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
"getcpu\0"
"process_vm_readv\0"
"process_vm_writev\0"
"";
/*
longest string: 22
total concatenated string lenght: 3022
pointer overhead: 2496
strings + overhead: 5518
total size aligned to max strlen 7176
*/
