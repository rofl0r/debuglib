static const syscalldef syscalldefs[] = {
	[SYSCALL_OR_NUM(0, SYS_restart_syscall)]	 = MAKE_UINT16(0, 1),
	[SYSCALL_OR_NUM(1, SYS__exit)]	 = MAKE_UINT16(1, 17),
	[SYSCALL_OR_NUM(2, SYS_fork)]	 = MAKE_UINT16(0, 23),
	[SYSCALL_OR_NUM(3, SYS_read)]	 = MAKE_UINT16(3, 28),
	[SYSCALL_OR_NUM(4, SYS_write)]	 = MAKE_UINT16(3, 33),
	[SYSCALL_OR_NUM(5, SYS_open)]	 = MAKE_UINT16(3, 39),
	[SYSCALL_OR_NUM(6, SYS_close)]	 = MAKE_UINT16(1, 44),
	[SYSCALL_OR_NUM(7, SYS_waitpid)]	 = MAKE_UINT16(3, 50),
	[SYSCALL_OR_NUM(8, SYS_creat)]	 = MAKE_UINT16(2, 58),
	[SYSCALL_OR_NUM(9, SYS_link)]	 = MAKE_UINT16(2, 64),
	[SYSCALL_OR_NUM(10, SYS_unlink)]	 = MAKE_UINT16(1, 69),
	[SYSCALL_OR_NUM(11, SYS_execve)]	 = MAKE_UINT16(3, 76),
	[SYSCALL_OR_NUM(12, SYS_chdir)]	 = MAKE_UINT16(1, 83),
	[SYSCALL_OR_NUM(13, SYS_time)]	 = MAKE_UINT16(1, 89),
	[SYSCALL_OR_NUM(14, SYS_mknod)]	 = MAKE_UINT16(3, 94),
	[SYSCALL_OR_NUM(15, SYS_chmod)]	 = MAKE_UINT16(2, 100),
	[SYSCALL_OR_NUM(16, SYS_lchown)]	 = MAKE_UINT16(3, 106),
	[SYSCALL_OR_NUM(17, SYS_break)]	 = MAKE_UINT16(0, 113),
	[SYSCALL_OR_NUM(18, SYS_oldstat)]	 = MAKE_UINT16(2, 119),
	[SYSCALL_OR_NUM(19, SYS_lseek)]	 = MAKE_UINT16(3, 127),
	[SYSCALL_OR_NUM(20, SYS_getpid)]	 = MAKE_UINT16(0, 133),
	[SYSCALL_OR_NUM(21, SYS_mount)]	 = MAKE_UINT16(5, 140),
	[SYSCALL_OR_NUM(22, SYS_oldumount)]	 = MAKE_UINT16(1, 146),
	[SYSCALL_OR_NUM(23, SYS_setuid)]	 = MAKE_UINT16(1, 156),
	[SYSCALL_OR_NUM(24, SYS_getuid)]	 = MAKE_UINT16(0, 163),
	[SYSCALL_OR_NUM(25, SYS_stime)]	 = MAKE_UINT16(1, 170),
	[SYSCALL_OR_NUM(26, SYS_ptrace)]	 = MAKE_UINT16(4, 176),
	[SYSCALL_OR_NUM(27, SYS_alarm)]	 = MAKE_UINT16(1, 183),
	[SYSCALL_OR_NUM(28, SYS_oldfstat)]	 = MAKE_UINT16(2, 189),
	[SYSCALL_OR_NUM(29, SYS_pause)]	 = MAKE_UINT16(0, 198),
	[SYSCALL_OR_NUM(30, SYS_utime)]	 = MAKE_UINT16(2, 204),
	[SYSCALL_OR_NUM(31, SYS_stty)]	 = MAKE_UINT16(2, 210),
	[SYSCALL_OR_NUM(32, SYS_gtty)]	 = MAKE_UINT16(2, 215),
	[SYSCALL_OR_NUM(33, SYS_access)]	 = MAKE_UINT16(2, 220),
	[SYSCALL_OR_NUM(34, SYS_nice)]	 = MAKE_UINT16(1, 227),
	[SYSCALL_OR_NUM(35, SYS_ftime)]	 = MAKE_UINT16(0, 232),
	[SYSCALL_OR_NUM(36, SYS_sync)]	 = MAKE_UINT16(0, 238),
	[SYSCALL_OR_NUM(37, SYS_kill)]	 = MAKE_UINT16(2, 243),
	[SYSCALL_OR_NUM(38, SYS_rename)]	 = MAKE_UINT16(2, 248),
	[SYSCALL_OR_NUM(39, SYS_mkdir)]	 = MAKE_UINT16(2, 255),
	[SYSCALL_OR_NUM(40, SYS_rmdir)]	 = MAKE_UINT16(1, 261),
	[SYSCALL_OR_NUM(41, SYS_dup)]	 = MAKE_UINT16(1, 267),
	[SYSCALL_OR_NUM(42, SYS_pipe)]	 = MAKE_UINT16(1, 271),
	[SYSCALL_OR_NUM(43, SYS_times)]	 = MAKE_UINT16(1, 276),
	[SYSCALL_OR_NUM(44, SYS_prof)]	 = MAKE_UINT16(0, 282),
	[SYSCALL_OR_NUM(45, SYS_brk)]	 = MAKE_UINT16(1, 287),
	[SYSCALL_OR_NUM(46, SYS_setgid)]	 = MAKE_UINT16(1, 291),
	[SYSCALL_OR_NUM(47, SYS_getgid)]	 = MAKE_UINT16(0, 298),
	[SYSCALL_OR_NUM(48, SYS_signal)]	 = MAKE_UINT16(3, 305),
	[SYSCALL_OR_NUM(49, SYS_geteuid)]	 = MAKE_UINT16(0, 312),
	[SYSCALL_OR_NUM(50, SYS_getegid)]	 = MAKE_UINT16(0, 320),
	[SYSCALL_OR_NUM(51, SYS_acct)]	 = MAKE_UINT16(1, 328),
	[SYSCALL_OR_NUM(52, SYS_umount)]	 = MAKE_UINT16(2, 333),
	[SYSCALL_OR_NUM(53, SYS_lock)]	 = MAKE_UINT16(0, 340),
	[SYSCALL_OR_NUM(54, SYS_ioctl)]	 = MAKE_UINT16(3, 345),
	[SYSCALL_OR_NUM(55, SYS_fcntl)]	 = MAKE_UINT16(3, 351),
	[SYSCALL_OR_NUM(56, SYS_mpx)]	 = MAKE_UINT16(0, 357),
	[SYSCALL_OR_NUM(57, SYS_setpgid)]	 = MAKE_UINT16(2, 361),
	[SYSCALL_OR_NUM(58, SYS_ulimit)]	 = MAKE_UINT16(2, 369),
	[SYSCALL_OR_NUM(59, SYS_oldolduname)]	 = MAKE_UINT16(1, 376),
	[SYSCALL_OR_NUM(60, SYS_umask)]	 = MAKE_UINT16(1, 388),
	[SYSCALL_OR_NUM(61, SYS_chroot)]	 = MAKE_UINT16(1, 394),
	[SYSCALL_OR_NUM(62, SYS_ustat)]	 = MAKE_UINT16(2, 401),
	[SYSCALL_OR_NUM(63, SYS_dup2)]	 = MAKE_UINT16(2, 407),
	[SYSCALL_OR_NUM(64, SYS_getppid)]	 = MAKE_UINT16(0, 412),
	[SYSCALL_OR_NUM(65, SYS_getpgrp)]	 = MAKE_UINT16(0, 420),
	[SYSCALL_OR_NUM(66, SYS_setsid)]	 = MAKE_UINT16(0, 428),
	[SYSCALL_OR_NUM(67, SYS_sigaction)]	 = MAKE_UINT16(3, 435),
	[SYSCALL_OR_NUM(68, SYS_sgetmask)]	 = MAKE_UINT16(0, 445),
	[SYSCALL_OR_NUM(69, SYS_ssetmask)]	 = MAKE_UINT16(1, 454),
	[SYSCALL_OR_NUM(70, SYS_setreuid)]	 = MAKE_UINT16(2, 463),
	[SYSCALL_OR_NUM(71, SYS_setregid)]	 = MAKE_UINT16(2, 472),
	[SYSCALL_OR_NUM(72, SYS_sigsuspend)]	 = MAKE_UINT16(3, 481),
	[SYSCALL_OR_NUM(73, SYS_sigpending)]	 = MAKE_UINT16(1, 492),
	[SYSCALL_OR_NUM(74, SYS_sethostname)]	 = MAKE_UINT16(2, 503),
	[SYSCALL_OR_NUM(75, SYS_setrlimit)]	 = MAKE_UINT16(2, 515),
	[SYSCALL_OR_NUM(76, SYS_old_getrlimit)]	 = MAKE_UINT16(2, 525),
	[SYSCALL_OR_NUM(77, SYS_getrusage)]	 = MAKE_UINT16(2, 539),
	[SYSCALL_OR_NUM(78, SYS_gettimeofday)]	 = MAKE_UINT16(2, 549),
	[SYSCALL_OR_NUM(79, SYS_settimeofday)]	 = MAKE_UINT16(2, 562),
	[SYSCALL_OR_NUM(80, SYS_getgroups)]	 = MAKE_UINT16(2, 575),
	[SYSCALL_OR_NUM(81, SYS_setgroups)]	 = MAKE_UINT16(2, 585),
	[SYSCALL_OR_NUM(82, SYS_oldselect)]	 = MAKE_UINT16(1, 595),
	[SYSCALL_OR_NUM(83, SYS_symlink)]	 = MAKE_UINT16(2, 605),
	[SYSCALL_OR_NUM(84, SYS_oldlstat)]	 = MAKE_UINT16(2, 613),
	[SYSCALL_OR_NUM(85, SYS_readlink)]	 = MAKE_UINT16(3, 622),
	[SYSCALL_OR_NUM(86, SYS_uselib)]	 = MAKE_UINT16(1, 631),
	[SYSCALL_OR_NUM(87, SYS_swapon)]	 = MAKE_UINT16(2, 638),
	[SYSCALL_OR_NUM(88, SYS_reboot)]	 = MAKE_UINT16(4, 645),
	[SYSCALL_OR_NUM(89, SYS_readdir)]	 = MAKE_UINT16(3, 652),
	[SYSCALL_OR_NUM(90, SYS_old_mmap)]	 = MAKE_UINT16(6, 660),
	[SYSCALL_OR_NUM(91, SYS_munmap)]	 = MAKE_UINT16(2, 669),
	[SYSCALL_OR_NUM(92, SYS_truncate)]	 = MAKE_UINT16(2, 676),
	[SYSCALL_OR_NUM(93, SYS_ftruncate)]	 = MAKE_UINT16(2, 685),
	[SYSCALL_OR_NUM(94, SYS_fchmod)]	 = MAKE_UINT16(2, 695),
	[SYSCALL_OR_NUM(95, SYS_fchown)]	 = MAKE_UINT16(3, 702),
	[SYSCALL_OR_NUM(96, SYS_getpriority)]	 = MAKE_UINT16(2, 709),
	[SYSCALL_OR_NUM(97, SYS_setpriority)]	 = MAKE_UINT16(3, 721),
	[SYSCALL_OR_NUM(98, SYS_profil)]	 = MAKE_UINT16(4, 733),
	[SYSCALL_OR_NUM(99, SYS_statfs)]	 = MAKE_UINT16(2, 740),
	[SYSCALL_OR_NUM(100, SYS_fstatfs)]	 = MAKE_UINT16(2, 747),
	[SYSCALL_OR_NUM(101, SYS_ioperm)]	 = MAKE_UINT16(3, 755),
	[SYSCALL_OR_NUM(102, SYS_socketcall)]	 = MAKE_UINT16(2, 762),
	[SYSCALL_OR_NUM(103, SYS_syslog)]	 = MAKE_UINT16(3, 773),
	[SYSCALL_OR_NUM(104, SYS_setitimer)]	 = MAKE_UINT16(3, 780),
	[SYSCALL_OR_NUM(105, SYS_getitimer)]	 = MAKE_UINT16(2, 790),
	[SYSCALL_OR_NUM(106, SYS_stat)]	 = MAKE_UINT16(2, 800),
	[SYSCALL_OR_NUM(107, SYS_lstat)]	 = MAKE_UINT16(2, 805),
	[SYSCALL_OR_NUM(108, SYS_fstat)]	 = MAKE_UINT16(2, 811),
	[SYSCALL_OR_NUM(109, SYS_olduname)]	 = MAKE_UINT16(1, 817),
	[SYSCALL_OR_NUM(110, SYS_iopl)]	 = MAKE_UINT16(1, 826),
	[SYSCALL_OR_NUM(111, SYS_vhangup)]	 = MAKE_UINT16(0, 831),
	[SYSCALL_OR_NUM(112, SYS_idle)]	 = MAKE_UINT16(0, 839),
	[SYSCALL_OR_NUM(113, SYS_vm86old)]	 = MAKE_UINT16(1, 844),
	[SYSCALL_OR_NUM(114, SYS_wait4)]	 = MAKE_UINT16(4, 852),
	[SYSCALL_OR_NUM(115, SYS_swapoff)]	 = MAKE_UINT16(1, 858),
	[SYSCALL_OR_NUM(116, SYS_sysinfo)]	 = MAKE_UINT16(1, 866),
	[SYSCALL_OR_NUM(117, SYS_ipc)]	 = MAKE_UINT16(6, 874),
	[SYSCALL_OR_NUM(118, SYS_fsync)]	 = MAKE_UINT16(1, 878),
	[SYSCALL_OR_NUM(119, SYS_sigreturn)]	 = MAKE_UINT16(0, 884),
	[SYSCALL_OR_NUM(120, SYS_clone)]	 = MAKE_UINT16(5, 894),
	[SYSCALL_OR_NUM(121, SYS_setdomainname)]	 = MAKE_UINT16(2, 900),
	[SYSCALL_OR_NUM(122, SYS_uname)]	 = MAKE_UINT16(1, 914),
	[SYSCALL_OR_NUM(123, SYS_modify_ldt)]	 = MAKE_UINT16(3, 920),
	[SYSCALL_OR_NUM(124, SYS_adjtimex)]	 = MAKE_UINT16(1, 931),
	[SYSCALL_OR_NUM(125, SYS_mprotect)]	 = MAKE_UINT16(3, 940),
	[SYSCALL_OR_NUM(126, SYS_sigprocmask)]	 = MAKE_UINT16(3, 949),
	[SYSCALL_OR_NUM(127, SYS_create_module)]	 = MAKE_UINT16(2, 961),
	[SYSCALL_OR_NUM(128, SYS_init_module)]	 = MAKE_UINT16(3, 975),
	[SYSCALL_OR_NUM(129, SYS_delete_module)]	 = MAKE_UINT16(2, 987),
	[SYSCALL_OR_NUM(130, SYS_get_kernel_syms)]	 = MAKE_UINT16(1, 1001),
	[SYSCALL_OR_NUM(131, SYS_quotactl)]	 = MAKE_UINT16(4, 1017),
	[SYSCALL_OR_NUM(132, SYS_getpgid)]	 = MAKE_UINT16(1, 1026),
	[SYSCALL_OR_NUM(133, SYS_fchdir)]	 = MAKE_UINT16(1, 1034),
	[SYSCALL_OR_NUM(134, SYS_bdflush)]	 = MAKE_UINT16(0, 1041),
	[SYSCALL_OR_NUM(135, SYS_sysfs)]	 = MAKE_UINT16(3, 1049),
	[SYSCALL_OR_NUM(136, SYS_personality)]	 = MAKE_UINT16(1, 1055),
	[SYSCALL_OR_NUM(137, SYS_afs_syscall)]	 = MAKE_UINT16(5, 1067),
	[SYSCALL_OR_NUM(138, SYS_setfsuid)]	 = MAKE_UINT16(1, 1079),
	[SYSCALL_OR_NUM(139, SYS_setfsgid)]	 = MAKE_UINT16(1, 1088),
	[SYSCALL_OR_NUM(140, SYS__llseek)]	 = MAKE_UINT16(5, 1097),
	[SYSCALL_OR_NUM(141, SYS_getdents)]	 = MAKE_UINT16(3, 1105),
	[SYSCALL_OR_NUM(142, SYS_select)]	 = MAKE_UINT16(5, 1114),
	[SYSCALL_OR_NUM(143, SYS_flock)]	 = MAKE_UINT16(2, 1121),
	[SYSCALL_OR_NUM(144, SYS_msync)]	 = MAKE_UINT16(3, 1127),
	[SYSCALL_OR_NUM(145, SYS_readv)]	 = MAKE_UINT16(3, 1133),
	[SYSCALL_OR_NUM(146, SYS_writev)]	 = MAKE_UINT16(3, 1139),
	[SYSCALL_OR_NUM(147, SYS_getsid)]	 = MAKE_UINT16(1, 1146),
	[SYSCALL_OR_NUM(148, SYS_fdatasync)]	 = MAKE_UINT16(1, 1153),
	[SYSCALL_OR_NUM(149, SYS__sysctl)]	 = MAKE_UINT16(1, 1163),
	[SYSCALL_OR_NUM(150, SYS_mlock)]	 = MAKE_UINT16(2, 1171),
	[SYSCALL_OR_NUM(151, SYS_munlock)]	 = MAKE_UINT16(2, 1177),
	[SYSCALL_OR_NUM(152, SYS_mlockall)]	 = MAKE_UINT16(1, 1185),
	[SYSCALL_OR_NUM(153, SYS_munlockall)]	 = MAKE_UINT16(0, 1194),
	[SYSCALL_OR_NUM(154, SYS_sched_setparam)]	 = MAKE_UINT16(0, 1205),
	[SYSCALL_OR_NUM(155, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1220),
	[SYSCALL_OR_NUM(156, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1235),
	[SYSCALL_OR_NUM(157, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1254),
	[SYSCALL_OR_NUM(158, SYS_sched_yield)]	 = MAKE_UINT16(0, 1273),
	[SYSCALL_OR_NUM(159, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1285),
	[SYSCALL_OR_NUM(160, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1308),
	[SYSCALL_OR_NUM(161, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1331),
	[SYSCALL_OR_NUM(162, SYS_nanosleep)]	 = MAKE_UINT16(2, 1353),
	[SYSCALL_OR_NUM(163, SYS_mremap)]	 = MAKE_UINT16(5, 1363),
	[SYSCALL_OR_NUM(164, SYS_setresuid)]	 = MAKE_UINT16(3, 1370),
	[SYSCALL_OR_NUM(165, SYS_getresuid)]	 = MAKE_UINT16(3, 1380),
	[SYSCALL_OR_NUM(166, SYS_vm86)]	 = MAKE_UINT16(5, 1390),
	[SYSCALL_OR_NUM(167, SYS_query_module)]	 = MAKE_UINT16(5, 1395),
	[SYSCALL_OR_NUM(168, SYS_poll)]	 = MAKE_UINT16(3, 1408),
	[SYSCALL_OR_NUM(169, SYS_nfsservctl)]	 = MAKE_UINT16(3, 1413),
	[SYSCALL_OR_NUM(170, SYS_setresgid)]	 = MAKE_UINT16(3, 1424),
	[SYSCALL_OR_NUM(171, SYS_getresgid)]	 = MAKE_UINT16(3, 1434),
	[SYSCALL_OR_NUM(172, SYS_prctl)]	 = MAKE_UINT16(5, 1444),
	[SYSCALL_OR_NUM(173, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 1450),
	[SYSCALL_OR_NUM(174, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 1463),
	[SYSCALL_OR_NUM(175, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 1476),
	[SYSCALL_OR_NUM(176, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 1491),
	[SYSCALL_OR_NUM(177, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 1505),
	[SYSCALL_OR_NUM(178, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 1521),
	[SYSCALL_OR_NUM(179, SYS_rt_sigsuspend)]	 = MAKE_UINT16(2, 1537),
	[SYSCALL_OR_NUM(180, SYS_pread64)]	 = MAKE_UINT16(5, 1551),
	[SYSCALL_OR_NUM(181, SYS_pwrite64)]	 = MAKE_UINT16(5, 1559),
	[SYSCALL_OR_NUM(182, SYS_chown)]	 = MAKE_UINT16(3, 1568),
	[SYSCALL_OR_NUM(183, SYS_getcwd)]	 = MAKE_UINT16(2, 1574),
	[SYSCALL_OR_NUM(184, SYS_capget)]	 = MAKE_UINT16(2, 1581),
	[SYSCALL_OR_NUM(185, SYS_capset)]	 = MAKE_UINT16(2, 1588),
	[SYSCALL_OR_NUM(186, SYS_sigaltstack)]	 = MAKE_UINT16(2, 1595),
	[SYSCALL_OR_NUM(187, SYS_sendfile)]	 = MAKE_UINT16(4, 1607),
	[SYSCALL_OR_NUM(188, SYS_getpmsg)]	 = MAKE_UINT16(5, 1616),
	[SYSCALL_OR_NUM(189, SYS_putpmsg)]	 = MAKE_UINT16(5, 1624),
	[SYSCALL_OR_NUM(190, SYS_vfork)]	 = MAKE_UINT16(0, 1632),
	[SYSCALL_OR_NUM(191, SYS_getrlimit)]	 = MAKE_UINT16(2, 1638),
	[SYSCALL_OR_NUM(192, SYS_mmap2)]	 = MAKE_UINT16(6, 1648),
	[SYSCALL_OR_NUM(193, SYS_truncate64)]	 = MAKE_UINT16(3, 1654),
	[SYSCALL_OR_NUM(194, SYS_ftruncate64)]	 = MAKE_UINT16(3, 1665),
	[SYSCALL_OR_NUM(195, SYS_stat64)]	 = MAKE_UINT16(2, 1677),
	[SYSCALL_OR_NUM(196, SYS_lstat64)]	 = MAKE_UINT16(2, 1684),
	[SYSCALL_OR_NUM(197, SYS_fstat64)]	 = MAKE_UINT16(2, 1692),
	[SYSCALL_OR_NUM(198, SYS_lchown32)]	 = MAKE_UINT16(3, 1700),
	[SYSCALL_OR_NUM(199, SYS_getuid32)]	 = MAKE_UINT16(0, 1709),
	[SYSCALL_OR_NUM(200, SYS_getgid32)]	 = MAKE_UINT16(0, 1718),
	[SYSCALL_OR_NUM(201, SYS_geteuid32)]	 = MAKE_UINT16(0, 1727),
	[SYSCALL_OR_NUM(202, SYS_getegid32)]	 = MAKE_UINT16(0, 1737),
	[SYSCALL_OR_NUM(203, SYS_setreuid32)]	 = MAKE_UINT16(2, 1747),
	[SYSCALL_OR_NUM(204, SYS_setregid32)]	 = MAKE_UINT16(2, 1758),
	[SYSCALL_OR_NUM(205, SYS_getgroups32)]	 = MAKE_UINT16(2, 1769),
	[SYSCALL_OR_NUM(206, SYS_setgroups32)]	 = MAKE_UINT16(2, 1781),
	[SYSCALL_OR_NUM(207, SYS_fchown32)]	 = MAKE_UINT16(3, 1793),
	[SYSCALL_OR_NUM(208, SYS_setresuid32)]	 = MAKE_UINT16(3, 1802),
	[SYSCALL_OR_NUM(209, SYS_getresuid32)]	 = MAKE_UINT16(3, 1814),
	[SYSCALL_OR_NUM(210, SYS_setresgid32)]	 = MAKE_UINT16(3, 1826),
	[SYSCALL_OR_NUM(211, SYS_getresgid32)]	 = MAKE_UINT16(3, 1838),
	[SYSCALL_OR_NUM(212, SYS_chown32)]	 = MAKE_UINT16(3, 1850),
	[SYSCALL_OR_NUM(213, SYS_setuid32)]	 = MAKE_UINT16(1, 1858),
	[SYSCALL_OR_NUM(214, SYS_setgid32)]	 = MAKE_UINT16(1, 1867),
	[SYSCALL_OR_NUM(215, SYS_setfsuid32)]	 = MAKE_UINT16(1, 1876),
	[SYSCALL_OR_NUM(216, SYS_setfsgid32)]	 = MAKE_UINT16(1, 1887),
	[SYSCALL_OR_NUM(217, SYS_pivot_root)]	 = MAKE_UINT16(2, 1898),
	[SYSCALL_OR_NUM(218, SYS_mincore)]	 = MAKE_UINT16(3, 1909),
	[SYSCALL_OR_NUM(219, SYS_madvise)]	 = MAKE_UINT16(3, 1917),
	[SYSCALL_OR_NUM(220, SYS_getdents64)]	 = MAKE_UINT16(3, 1925),
	[SYSCALL_OR_NUM(221, SYS_fcntl64)]	 = MAKE_UINT16(3, 1936),
	[SYSCALL_OR_NUM(224, SYS_gettid)]	 = MAKE_UINT16(0, 1944),
	[SYSCALL_OR_NUM(225, SYS_readahead)]	 = MAKE_UINT16(4, 1951),
	[SYSCALL_OR_NUM(226, SYS_setxattr)]	 = MAKE_UINT16(5, 1961),
	[SYSCALL_OR_NUM(227, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1970),
	[SYSCALL_OR_NUM(228, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1980),
	[SYSCALL_OR_NUM(229, SYS_getxattr)]	 = MAKE_UINT16(4, 1990),
	[SYSCALL_OR_NUM(230, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1999),
	[SYSCALL_OR_NUM(231, SYS_fgetxattr)]	 = MAKE_UINT16(4, 2009),
	[SYSCALL_OR_NUM(232, SYS_listxattr)]	 = MAKE_UINT16(3, 2019),
	[SYSCALL_OR_NUM(233, SYS_llistxattr)]	 = MAKE_UINT16(3, 2029),
	[SYSCALL_OR_NUM(234, SYS_flistxattr)]	 = MAKE_UINT16(3, 2040),
	[SYSCALL_OR_NUM(235, SYS_removexattr)]	 = MAKE_UINT16(2, 2051),
	[SYSCALL_OR_NUM(236, SYS_lremovexattr)]	 = MAKE_UINT16(2, 2063),
	[SYSCALL_OR_NUM(237, SYS_fremovexattr)]	 = MAKE_UINT16(2, 2076),
	[SYSCALL_OR_NUM(238, SYS_tkill)]	 = MAKE_UINT16(2, 2089),
	[SYSCALL_OR_NUM(239, SYS_sendfile64)]	 = MAKE_UINT16(4, 2095),
	[SYSCALL_OR_NUM(240, SYS_futex)]	 = MAKE_UINT16(6, 2106),
	[SYSCALL_OR_NUM(241, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 2112),
	[SYSCALL_OR_NUM(242, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 2130),
	[SYSCALL_OR_NUM(243, SYS_set_thread_area)]	 = MAKE_UINT16(1, 2148),
	[SYSCALL_OR_NUM(244, SYS_get_thread_area)]	 = MAKE_UINT16(1, 2164),
	[SYSCALL_OR_NUM(245, SYS_io_setup)]	 = MAKE_UINT16(2, 2180),
	[SYSCALL_OR_NUM(246, SYS_io_destroy)]	 = MAKE_UINT16(1, 2189),
	[SYSCALL_OR_NUM(247, SYS_io_getevents)]	 = MAKE_UINT16(5, 2200),
	[SYSCALL_OR_NUM(248, SYS_io_submit)]	 = MAKE_UINT16(3, 2213),
	[SYSCALL_OR_NUM(249, SYS_io_cancel)]	 = MAKE_UINT16(3, 2223),
	[SYSCALL_OR_NUM(250, SYS_fadvise64)]	 = MAKE_UINT16(5, 2233),
	[SYSCALL_OR_NUM(252, SYS_exit_group)]	 = MAKE_UINT16(1, 2243),
	[SYSCALL_OR_NUM(253, SYS_lookup_dcookie)]	 = MAKE_UINT16(4, 2254),
	[SYSCALL_OR_NUM(254, SYS_epoll_create)]	 = MAKE_UINT16(1, 2269),
	[SYSCALL_OR_NUM(255, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 2282),
	[SYSCALL_OR_NUM(256, SYS_epoll_wait)]	 = MAKE_UINT16(4, 2292),
	[SYSCALL_OR_NUM(257, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 2303),
	[SYSCALL_OR_NUM(258, SYS_set_tid_address)]	 = MAKE_UINT16(1, 2320),
	[SYSCALL_OR_NUM(259, SYS_timer_create)]	 = MAKE_UINT16(3, 2336),
	[SYSCALL_OR_NUM(260, SYS_timer_settime)]	 = MAKE_UINT16(4, 2349),
	[SYSCALL_OR_NUM(261, SYS_timer_gettime)]	 = MAKE_UINT16(2, 2363),
	[SYSCALL_OR_NUM(262, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2377),
	[SYSCALL_OR_NUM(263, SYS_timer_delete)]	 = MAKE_UINT16(1, 2394),
	[SYSCALL_OR_NUM(264, SYS_clock_settime)]	 = MAKE_UINT16(2, 2407),
	[SYSCALL_OR_NUM(265, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2421),
	[SYSCALL_OR_NUM(266, SYS_clock_getres)]	 = MAKE_UINT16(2, 2435),
	[SYSCALL_OR_NUM(267, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2448),
	[SYSCALL_OR_NUM(268, SYS_statfs64)]	 = MAKE_UINT16(3, 2464),
	[SYSCALL_OR_NUM(269, SYS_fstatfs64)]	 = MAKE_UINT16(2, 2473),
	[SYSCALL_OR_NUM(270, SYS_tgkill)]	 = MAKE_UINT16(3, 2483),
	[SYSCALL_OR_NUM(271, SYS_utimes)]	 = MAKE_UINT16(2, 2490),
	[SYSCALL_OR_NUM(272, SYS_fadvise64_64)]	 = MAKE_UINT16(6, 2497),
	[SYSCALL_OR_NUM(273, SYS_vserver)]	 = MAKE_UINT16(5, 2510),
	[SYSCALL_OR_NUM(274, SYS_mbind)]	 = MAKE_UINT16(4, 2518),
	[SYSCALL_OR_NUM(275, SYS_get_mempolicy)]	 = MAKE_UINT16(5, 2524),
	[SYSCALL_OR_NUM(276, SYS_set_mempolicy)]	 = MAKE_UINT16(3, 2538),
	[SYSCALL_OR_NUM(277, SYS_mq_open)]	 = MAKE_UINT16(4, 2552),
	[SYSCALL_OR_NUM(278, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2560),
	[SYSCALL_OR_NUM(279, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2570),
	[SYSCALL_OR_NUM(280, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2583),
	[SYSCALL_OR_NUM(281, SYS_mq_notify)]	 = MAKE_UINT16(2, 2599),
	[SYSCALL_OR_NUM(282, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2609),
	[SYSCALL_OR_NUM(283, SYS_kexec_load)]	 = MAKE_UINT16(4, 2623),
	[SYSCALL_OR_NUM(284, SYS_waitid)]	 = MAKE_UINT16(5, 2634),
	[SYSCALL_OR_NUM(286, SYS_add_key)]	 = MAKE_UINT16(5, 2641),
	[SYSCALL_OR_NUM(287, SYS_request_key)]	 = MAKE_UINT16(4, 2649),
	[SYSCALL_OR_NUM(288, SYS_keyctl)]	 = MAKE_UINT16(5, 2661),
	[SYSCALL_OR_NUM(289, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2668),
	[SYSCALL_OR_NUM(290, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2679),
	[SYSCALL_OR_NUM(291, SYS_inotify_init)]	 = MAKE_UINT16(0, 2690),
	[SYSCALL_OR_NUM(292, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2703),
	[SYSCALL_OR_NUM(293, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2721),
	[SYSCALL_OR_NUM(294, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2738),
	[SYSCALL_OR_NUM(295, SYS_openat)]	 = MAKE_UINT16(4, 2752),
	[SYSCALL_OR_NUM(296, SYS_mkdirat)]	 = MAKE_UINT16(3, 2759),
	[SYSCALL_OR_NUM(297, SYS_mknodat)]	 = MAKE_UINT16(4, 2767),
	[SYSCALL_OR_NUM(298, SYS_fchownat)]	 = MAKE_UINT16(5, 2775),
	[SYSCALL_OR_NUM(299, SYS_futimesat)]	 = MAKE_UINT16(3, 2784),
	[SYSCALL_OR_NUM(300, SYS_fstatat64)]	 = MAKE_UINT16(4, 2794),
	[SYSCALL_OR_NUM(301, SYS_unlinkat)]	 = MAKE_UINT16(3, 2804),
	[SYSCALL_OR_NUM(302, SYS_renameat)]	 = MAKE_UINT16(4, 2813),
	[SYSCALL_OR_NUM(303, SYS_linkat)]	 = MAKE_UINT16(5, 2822),
	[SYSCALL_OR_NUM(304, SYS_symlinkat)]	 = MAKE_UINT16(3, 2829),
	[SYSCALL_OR_NUM(305, SYS_readlinkat)]	 = MAKE_UINT16(4, 2839),
	[SYSCALL_OR_NUM(306, SYS_fchmodat)]	 = MAKE_UINT16(3, 2850),
	[SYSCALL_OR_NUM(307, SYS_faccessat)]	 = MAKE_UINT16(3, 2859),
	[SYSCALL_OR_NUM(308, SYS_pselect6)]	 = MAKE_UINT16(6, 2869),
	[SYSCALL_OR_NUM(309, SYS_ppoll)]	 = MAKE_UINT16(5, 2878),
	[SYSCALL_OR_NUM(310, SYS_unshare)]	 = MAKE_UINT16(1, 2884),
	[SYSCALL_OR_NUM(311, SYS_set_robust_list)]	 = MAKE_UINT16(2, 2892),
	[SYSCALL_OR_NUM(312, SYS_get_robust_list)]	 = MAKE_UINT16(3, 2908),
	[SYSCALL_OR_NUM(313, SYS_splice)]	 = MAKE_UINT16(6, 2924),
	[SYSCALL_OR_NUM(314, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2931),
	[SYSCALL_OR_NUM(315, SYS_tee)]	 = MAKE_UINT16(4, 2947),
	[SYSCALL_OR_NUM(316, SYS_vmsplice)]	 = MAKE_UINT16(5, 2951),
	[SYSCALL_OR_NUM(317, SYS_move_pages)]	 = MAKE_UINT16(6, 2960),
	[SYSCALL_OR_NUM(318, SYS_getcpu)]	 = MAKE_UINT16(3, 2971),
	[SYSCALL_OR_NUM(319, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2978),
	[SYSCALL_OR_NUM(320, SYS_utimensat)]	 = MAKE_UINT16(4, 2990),
	[SYSCALL_OR_NUM(321, SYS_signalfd)]	 = MAKE_UINT16(3, 3000),
	[SYSCALL_OR_NUM(322, SYS_timerfd_create)]	 = MAKE_UINT16(2, 3009),
	[SYSCALL_OR_NUM(323, SYS_eventfd)]	 = MAKE_UINT16(1, 3024),
	[SYSCALL_OR_NUM(324, SYS_fallocate)]	 = MAKE_UINT16(6, 3032),
	[SYSCALL_OR_NUM(325, SYS_semtimedop)]	 = MAKE_UINT16(5, 3042),
	[SYSCALL_OR_NUM(326, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 3053),
	[SYSCALL_OR_NUM(327, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 3069),
	[SYSCALL_OR_NUM(328, SYS_semctl)]	 = MAKE_UINT16(4, 3085),
	[SYSCALL_OR_NUM(329, SYS_semget)]	 = MAKE_UINT16(4, 3092),
	[SYSCALL_OR_NUM(330, SYS_semop)]	 = MAKE_UINT16(4, 3099),
	[SYSCALL_OR_NUM(331, SYS_msgctl)]	 = MAKE_UINT16(4, 3105),
	[SYSCALL_OR_NUM(332, SYS_msgget)]	 = MAKE_UINT16(4, 3112),
	[SYSCALL_OR_NUM(333, SYS_msgrcv)]	 = MAKE_UINT16(4, 3119),
	[SYSCALL_OR_NUM(334, SYS_msgsnd)]	 = MAKE_UINT16(4, 3126),
	[SYSCALL_OR_NUM(335, SYS_shmat)]	 = MAKE_UINT16(4, 3133),
	[SYSCALL_OR_NUM(336, SYS_shmctl)]	 = MAKE_UINT16(4, 3139),
	[SYSCALL_OR_NUM(337, SYS_shmdt)]	 = MAKE_UINT16(4, 3146),
	[SYSCALL_OR_NUM(338, SYS_shmget)]	 = MAKE_UINT16(4, 3152),
	[SYSCALL_OR_NUM(339, SYS_signalfd4)]	 = MAKE_UINT16(4, 3159),
	[SYSCALL_OR_NUM(340, SYS_eventfd2)]	 = MAKE_UINT16(2, 3169),
	[SYSCALL_OR_NUM(341, SYS_epoll_create1)]	 = MAKE_UINT16(1, 3178),
	[SYSCALL_OR_NUM(342, SYS_dup3)]	 = MAKE_UINT16(3, 3192),
	[SYSCALL_OR_NUM(343, SYS_pipe2)]	 = MAKE_UINT16(2, 3197),
	[SYSCALL_OR_NUM(344, SYS_inotify_init1)]	 = MAKE_UINT16(1, 3203),
	[SYSCALL_OR_NUM(345, SYS_socket)]	 = MAKE_UINT16(3, 3217),
	[SYSCALL_OR_NUM(346, SYS_socketpair)]	 = MAKE_UINT16(4, 3224),
	[SYSCALL_OR_NUM(347, SYS_bind)]	 = MAKE_UINT16(3, 3235),
	[SYSCALL_OR_NUM(348, SYS_listen)]	 = MAKE_UINT16(2, 3240),
	[SYSCALL_OR_NUM(349, SYS_accept)]	 = MAKE_UINT16(3, 3247),
	[SYSCALL_OR_NUM(350, SYS_connect)]	 = MAKE_UINT16(3, 3254),
	[SYSCALL_OR_NUM(351, SYS_getsockname)]	 = MAKE_UINT16(3, 3262),
	[SYSCALL_OR_NUM(352, SYS_getpeername)]	 = MAKE_UINT16(3, 3274),
	[SYSCALL_OR_NUM(353, SYS_sendto)]	 = MAKE_UINT16(6, 3286),
	[SYSCALL_OR_NUM(354, SYS_send)]	 = MAKE_UINT16(4, 3293),
	[SYSCALL_OR_NUM(355, SYS_recvfrom)]	 = MAKE_UINT16(6, 3298),
	[SYSCALL_OR_NUM(356, SYS_recv)]	 = MAKE_UINT16(4, 3307),
	[SYSCALL_OR_NUM(357, SYS_setsockopt)]	 = MAKE_UINT16(5, 3312),
	[SYSCALL_OR_NUM(358, SYS_getsockopt)]	 = MAKE_UINT16(5, 3323),
	[SYSCALL_OR_NUM(359, SYS_shutdown)]	 = MAKE_UINT16(2, 3334),
	[SYSCALL_OR_NUM(360, SYS_sendmsg)]	 = MAKE_UINT16(3, 3343),
	[SYSCALL_OR_NUM(361, SYS_recvmsg)]	 = MAKE_UINT16(5, 3351),
	[SYSCALL_OR_NUM(362, SYS_accept4)]	 = MAKE_UINT16(4, 3359),
	[SYSCALL_OR_NUM(363, SYS_preadv)]	 = MAKE_UINT16(5, 3367),
	[SYSCALL_OR_NUM(364, SYS_pwritev)]	 = MAKE_UINT16(5, 3374),
	[SYSCALL_OR_NUM(365, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 3382),
	[SYSCALL_OR_NUM(366, SYS_perf_event_open)]	 = MAKE_UINT16(5, 3400),
	[SYSCALL_OR_NUM(367, SYS_recvmmsg)]	 = MAKE_UINT16(5, 3416),
	[SYSCALL_OR_NUM(368, SYS_fanotify_init)]	 = MAKE_UINT16(2, 3425),
	[SYSCALL_OR_NUM(369, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 3439),
	[SYSCALL_OR_NUM(370, SYS_prlimit64)]	 = MAKE_UINT16(4, 3453),
	[SYSCALL_OR_NUM(371, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 3463),
	[SYSCALL_OR_NUM(372, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 3481),
	[SYSCALL_OR_NUM(373, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 3499),
	[SYSCALL_OR_NUM(374, SYS_syncfs)]	 = MAKE_UINT16(1, 3513),
	[SYSCALL_OR_NUM(375, SYS_setns)]	 = MAKE_UINT16(2, 3520),
	[SYSCALL_OR_NUM(376, SYS_sendmmsg)]	 = MAKE_UINT16(4, 3526),
	[SYSCALL_OR_NUM(377, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 3535),
	[SYSCALL_OR_NUM(378, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 3552),
};

static const char syscallnames[] = "\0"
"restart_syscall\0"
"_exit\0"
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
"old_getrlimit\0"
"getrusage\0"
"gettimeofday\0"
"settimeofday\0"
"getgroups\0"
"setgroups\0"
"oldselect\0"
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
"vm86old\0"
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
"select\0"
"flock\0"
"msync\0"
"readv\0"
"writev\0"
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
"setresuid\0"
"getresuid\0"
"vm86\0"
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
"pread64\0"
"pwrite64\0"
"chown\0"
"getcwd\0"
"capget\0"
"capset\0"
"sigaltstack\0"
"sendfile\0"
"getpmsg\0"
"putpmsg\0"
"vfork\0"
"getrlimit\0"
"mmap2\0"
"truncate64\0"
"ftruncate64\0"
"stat64\0"
"lstat64\0"
"fstat64\0"
"lchown32\0"
"getuid32\0"
"getgid32\0"
"geteuid32\0"
"getegid32\0"
"setreuid32\0"
"setregid32\0"
"getgroups32\0"
"setgroups32\0"
"fchown32\0"
"setresuid32\0"
"getresuid32\0"
"setresgid32\0"
"getresgid32\0"
"chown32\0"
"setuid32\0"
"setgid32\0"
"setfsuid32\0"
"setfsgid32\0"
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
"set_thread_area\0"
"get_thread_area\0"
"io_setup\0"
"io_destroy\0"
"io_getevents\0"
"io_submit\0"
"io_cancel\0"
"fadvise64\0"
"exit_group\0"
"lookup_dcookie\0"
"epoll_create\0"
"epoll_ctl\0"
"epoll_wait\0"
"remap_file_pages\0"
"set_tid_address\0"
"timer_create\0"
"timer_settime\0"
"timer_gettime\0"
"timer_getoverrun\0"
"timer_delete\0"
"clock_settime\0"
"clock_gettime\0"
"clock_getres\0"
"clock_nanosleep\0"
"statfs64\0"
"fstatfs64\0"
"tgkill\0"
"utimes\0"
"fadvise64_64\0"
"vserver\0"
"mbind\0"
"get_mempolicy\0"
"set_mempolicy\0"
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
"fstatat64\0"
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
"sync_file_range\0"
"tee\0"
"vmsplice\0"
"move_pages\0"
"getcpu\0"
"epoll_pwait\0"
"utimensat\0"
"signalfd\0"
"timerfd_create\0"
"eventfd\0"
"fallocate\0"
"semtimedop\0"
"timerfd_settime\0"
"timerfd_gettime\0"
"semctl\0"
"semget\0"
"semop\0"
"msgctl\0"
"msgget\0"
"msgrcv\0"
"msgsnd\0"
"shmat\0"
"shmctl\0"
"shmdt\0"
"shmget\0"
"signalfd4\0"
"eventfd2\0"
"epoll_create1\0"
"dup3\0"
"pipe2\0"
"inotify_init1\0"
"socket\0"
"socketpair\0"
"bind\0"
"listen\0"
"accept\0"
"connect\0"
"getsockname\0"
"getpeername\0"
"sendto\0"
"send\0"
"recvfrom\0"
"recv\0"
"setsockopt\0"
"getsockopt\0"
"shutdown\0"
"sendmsg\0"
"recvmsg\0"
"accept4\0"
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
"setns\0"
"sendmmsg\0"
"process_vm_readv\0"
"process_vm_writev\0"
"";
/*
longest string: 22
total concatenated string length: 3569
pointer overhead: 3000
strings + overhead: 6569
total size aligned to max strlen 8625
*/
