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
	[SYSCALL_OR_NUM(13, SYS_64:rt_sigaction)]	 = MAKE_UINT16(4, 76),
	[SYSCALL_OR_NUM(14, SYS_rt_sigprocmask)]	 = MAKE_UINT16(4, 92),
	[SYSCALL_OR_NUM(15, SYS_64:rt_sigreturn)]	 = MAKE_UINT16(0, 107),
	[SYSCALL_OR_NUM(16, SYS_64:ioctl)]	 = MAKE_UINT16(3, 123),
	[SYSCALL_OR_NUM(17, SYS_pread)]	 = MAKE_UINT16(5, 132),
	[SYSCALL_OR_NUM(18, SYS_pwrite)]	 = MAKE_UINT16(5, 138),
	[SYSCALL_OR_NUM(19, SYS_64:readv)]	 = MAKE_UINT16(3, 145),
	[SYSCALL_OR_NUM(20, SYS_64:writev)]	 = MAKE_UINT16(3, 154),
	[SYSCALL_OR_NUM(21, SYS_access)]	 = MAKE_UINT16(2, 164),
	[SYSCALL_OR_NUM(22, SYS_pipe)]	 = MAKE_UINT16(1, 171),
	[SYSCALL_OR_NUM(23, SYS_select)]	 = MAKE_UINT16(5, 176),
	[SYSCALL_OR_NUM(24, SYS_sched_yield)]	 = MAKE_UINT16(0, 183),
	[SYSCALL_OR_NUM(25, SYS_mremap)]	 = MAKE_UINT16(5, 195),
	[SYSCALL_OR_NUM(26, SYS_msync)]	 = MAKE_UINT16(3, 202),
	[SYSCALL_OR_NUM(27, SYS_mincore)]	 = MAKE_UINT16(3, 208),
	[SYSCALL_OR_NUM(28, SYS_madvise)]	 = MAKE_UINT16(3, 216),
	[SYSCALL_OR_NUM(29, SYS_shmget)]	 = MAKE_UINT16(4, 224),
	[SYSCALL_OR_NUM(30, SYS_shmat)]	 = MAKE_UINT16(4, 231),
	[SYSCALL_OR_NUM(31, SYS_shmctl)]	 = MAKE_UINT16(4, 237),
	[SYSCALL_OR_NUM(32, SYS_dup)]	 = MAKE_UINT16(1, 244),
	[SYSCALL_OR_NUM(33, SYS_dup2)]	 = MAKE_UINT16(2, 248),
	[SYSCALL_OR_NUM(34, SYS_pause)]	 = MAKE_UINT16(0, 253),
	[SYSCALL_OR_NUM(35, SYS_nanosleep)]	 = MAKE_UINT16(2, 259),
	[SYSCALL_OR_NUM(36, SYS_getitimer)]	 = MAKE_UINT16(2, 269),
	[SYSCALL_OR_NUM(37, SYS_alarm)]	 = MAKE_UINT16(1, 279),
	[SYSCALL_OR_NUM(38, SYS_setitimer)]	 = MAKE_UINT16(3, 285),
	[SYSCALL_OR_NUM(39, SYS_getpid)]	 = MAKE_UINT16(0, 295),
	[SYSCALL_OR_NUM(40, SYS_sendfile)]	 = MAKE_UINT16(4, 302),
	[SYSCALL_OR_NUM(41, SYS_socket)]	 = MAKE_UINT16(3, 311),
	[SYSCALL_OR_NUM(42, SYS_connect)]	 = MAKE_UINT16(3, 318),
	[SYSCALL_OR_NUM(43, SYS_accept)]	 = MAKE_UINT16(3, 326),
	[SYSCALL_OR_NUM(44, SYS_sendto)]	 = MAKE_UINT16(6, 333),
	[SYSCALL_OR_NUM(45, SYS_64:recvfrom)]	 = MAKE_UINT16(6, 340),
	[SYSCALL_OR_NUM(46, SYS_64:sendmsg)]	 = MAKE_UINT16(3, 352),
	[SYSCALL_OR_NUM(47, SYS_64:recvmsg)]	 = MAKE_UINT16(5, 363),
	[SYSCALL_OR_NUM(48, SYS_shutdown)]	 = MAKE_UINT16(2, 374),
	[SYSCALL_OR_NUM(49, SYS_bind)]	 = MAKE_UINT16(3, 383),
	[SYSCALL_OR_NUM(50, SYS_listen)]	 = MAKE_UINT16(2, 388),
	[SYSCALL_OR_NUM(51, SYS_getsockname)]	 = MAKE_UINT16(3, 395),
	[SYSCALL_OR_NUM(52, SYS_getpeername)]	 = MAKE_UINT16(3, 407),
	[SYSCALL_OR_NUM(53, SYS_socketpair)]	 = MAKE_UINT16(4, 419),
	[SYSCALL_OR_NUM(54, SYS_64:setsockopt)]	 = MAKE_UINT16(5, 430),
	[SYSCALL_OR_NUM(55, SYS_64:getsockopt)]	 = MAKE_UINT16(5, 444),
	[SYSCALL_OR_NUM(56, SYS_clone)]	 = MAKE_UINT16(5, 458),
	[SYSCALL_OR_NUM(57, SYS_fork)]	 = MAKE_UINT16(0, 464),
	[SYSCALL_OR_NUM(58, SYS_vfork)]	 = MAKE_UINT16(0, 469),
	[SYSCALL_OR_NUM(59, SYS_64:execve)]	 = MAKE_UINT16(3, 475),
	[SYSCALL_OR_NUM(60, SYS__exit)]	 = MAKE_UINT16(1, 485),
	[SYSCALL_OR_NUM(61, SYS_wait4)]	 = MAKE_UINT16(4, 491),
	[SYSCALL_OR_NUM(62, SYS_kill)]	 = MAKE_UINT16(2, 497),
	[SYSCALL_OR_NUM(63, SYS_uname)]	 = MAKE_UINT16(1, 502),
	[SYSCALL_OR_NUM(64, SYS_semget)]	 = MAKE_UINT16(4, 508),
	[SYSCALL_OR_NUM(65, SYS_semop)]	 = MAKE_UINT16(4, 515),
	[SYSCALL_OR_NUM(66, SYS_semctl)]	 = MAKE_UINT16(4, 521),
	[SYSCALL_OR_NUM(67, SYS_shmdt)]	 = MAKE_UINT16(4, 528),
	[SYSCALL_OR_NUM(68, SYS_msgget)]	 = MAKE_UINT16(4, 534),
	[SYSCALL_OR_NUM(69, SYS_msgsnd)]	 = MAKE_UINT16(4, 541),
	[SYSCALL_OR_NUM(70, SYS_msgrcv)]	 = MAKE_UINT16(5, 548),
	[SYSCALL_OR_NUM(71, SYS_msgctl)]	 = MAKE_UINT16(3, 555),
	[SYSCALL_OR_NUM(72, SYS_fcntl)]	 = MAKE_UINT16(3, 562),
	[SYSCALL_OR_NUM(73, SYS_flock)]	 = MAKE_UINT16(2, 568),
	[SYSCALL_OR_NUM(74, SYS_fsync)]	 = MAKE_UINT16(1, 574),
	[SYSCALL_OR_NUM(75, SYS_fdatasync)]	 = MAKE_UINT16(1, 580),
	[SYSCALL_OR_NUM(76, SYS_truncate)]	 = MAKE_UINT16(2, 590),
	[SYSCALL_OR_NUM(77, SYS_ftruncate)]	 = MAKE_UINT16(2, 599),
	[SYSCALL_OR_NUM(78, SYS_getdents)]	 = MAKE_UINT16(3, 609),
	[SYSCALL_OR_NUM(79, SYS_getcwd)]	 = MAKE_UINT16(2, 618),
	[SYSCALL_OR_NUM(80, SYS_chdir)]	 = MAKE_UINT16(1, 625),
	[SYSCALL_OR_NUM(81, SYS_fchdir)]	 = MAKE_UINT16(1, 631),
	[SYSCALL_OR_NUM(82, SYS_rename)]	 = MAKE_UINT16(2, 638),
	[SYSCALL_OR_NUM(83, SYS_mkdir)]	 = MAKE_UINT16(2, 645),
	[SYSCALL_OR_NUM(84, SYS_rmdir)]	 = MAKE_UINT16(1, 651),
	[SYSCALL_OR_NUM(85, SYS_creat)]	 = MAKE_UINT16(2, 657),
	[SYSCALL_OR_NUM(86, SYS_link)]	 = MAKE_UINT16(2, 663),
	[SYSCALL_OR_NUM(87, SYS_unlink)]	 = MAKE_UINT16(1, 668),
	[SYSCALL_OR_NUM(88, SYS_symlink)]	 = MAKE_UINT16(2, 675),
	[SYSCALL_OR_NUM(89, SYS_readlink)]	 = MAKE_UINT16(3, 683),
	[SYSCALL_OR_NUM(90, SYS_chmod)]	 = MAKE_UINT16(2, 692),
	[SYSCALL_OR_NUM(91, SYS_fchmod)]	 = MAKE_UINT16(2, 698),
	[SYSCALL_OR_NUM(92, SYS_chown)]	 = MAKE_UINT16(3, 705),
	[SYSCALL_OR_NUM(93, SYS_fchown)]	 = MAKE_UINT16(3, 711),
	[SYSCALL_OR_NUM(94, SYS_lchown)]	 = MAKE_UINT16(3, 718),
	[SYSCALL_OR_NUM(95, SYS_umask)]	 = MAKE_UINT16(1, 725),
	[SYSCALL_OR_NUM(96, SYS_gettimeofday)]	 = MAKE_UINT16(2, 731),
	[SYSCALL_OR_NUM(97, SYS_getrlimit)]	 = MAKE_UINT16(2, 744),
	[SYSCALL_OR_NUM(98, SYS_getrusage)]	 = MAKE_UINT16(2, 754),
	[SYSCALL_OR_NUM(99, SYS_sysinfo)]	 = MAKE_UINT16(1, 764),
	[SYSCALL_OR_NUM(100, SYS_times)]	 = MAKE_UINT16(1, 772),
	[SYSCALL_OR_NUM(101, SYS_64:ptrace)]	 = MAKE_UINT16(4, 778),
	[SYSCALL_OR_NUM(102, SYS_getuid)]	 = MAKE_UINT16(0, 788),
	[SYSCALL_OR_NUM(103, SYS_syslog)]	 = MAKE_UINT16(3, 795),
	[SYSCALL_OR_NUM(104, SYS_getgid)]	 = MAKE_UINT16(0, 802),
	[SYSCALL_OR_NUM(105, SYS_setuid)]	 = MAKE_UINT16(1, 809),
	[SYSCALL_OR_NUM(106, SYS_setgid)]	 = MAKE_UINT16(1, 816),
	[SYSCALL_OR_NUM(107, SYS_geteuid)]	 = MAKE_UINT16(0, 823),
	[SYSCALL_OR_NUM(108, SYS_getegid)]	 = MAKE_UINT16(0, 831),
	[SYSCALL_OR_NUM(109, SYS_setpgid)]	 = MAKE_UINT16(2, 839),
	[SYSCALL_OR_NUM(110, SYS_getppid)]	 = MAKE_UINT16(0, 847),
	[SYSCALL_OR_NUM(111, SYS_getpgrp)]	 = MAKE_UINT16(0, 855),
	[SYSCALL_OR_NUM(112, SYS_setsid)]	 = MAKE_UINT16(0, 863),
	[SYSCALL_OR_NUM(113, SYS_setreuid)]	 = MAKE_UINT16(2, 870),
	[SYSCALL_OR_NUM(114, SYS_setregid)]	 = MAKE_UINT16(2, 879),
	[SYSCALL_OR_NUM(115, SYS_getgroups)]	 = MAKE_UINT16(2, 888),
	[SYSCALL_OR_NUM(116, SYS_setgroups)]	 = MAKE_UINT16(2, 898),
	[SYSCALL_OR_NUM(117, SYS_setresuid)]	 = MAKE_UINT16(3, 908),
	[SYSCALL_OR_NUM(118, SYS_getresuid)]	 = MAKE_UINT16(3, 918),
	[SYSCALL_OR_NUM(119, SYS_setresgid)]	 = MAKE_UINT16(3, 928),
	[SYSCALL_OR_NUM(120, SYS_getresgid)]	 = MAKE_UINT16(3, 938),
	[SYSCALL_OR_NUM(121, SYS_getpgid)]	 = MAKE_UINT16(1, 948),
	[SYSCALL_OR_NUM(122, SYS_setfsuid)]	 = MAKE_UINT16(1, 956),
	[SYSCALL_OR_NUM(123, SYS_setfsgid)]	 = MAKE_UINT16(1, 965),
	[SYSCALL_OR_NUM(124, SYS_getsid)]	 = MAKE_UINT16(1, 974),
	[SYSCALL_OR_NUM(125, SYS_capget)]	 = MAKE_UINT16(2, 981),
	[SYSCALL_OR_NUM(126, SYS_capset)]	 = MAKE_UINT16(2, 988),
	[SYSCALL_OR_NUM(127, SYS_64:rt_sigpending)]	 = MAKE_UINT16(2, 995),
	[SYSCALL_OR_NUM(128, SYS_64:rt_sigtimedwait)]	 = MAKE_UINT16(4, 1012),
	[SYSCALL_OR_NUM(129, SYS_64:rt_sigqueueinfo)]	 = MAKE_UINT16(3, 1031),
	[SYSCALL_OR_NUM(130, SYS_rt_sigsuspend)]	 = MAKE_UINT16(2, 1050),
	[SYSCALL_OR_NUM(131, SYS_64:sigaltstack)]	 = MAKE_UINT16(2, 1064),
	[SYSCALL_OR_NUM(132, SYS_utime)]	 = MAKE_UINT16(2, 1079),
	[SYSCALL_OR_NUM(133, SYS_mknod)]	 = MAKE_UINT16(3, 1085),
	[SYSCALL_OR_NUM(134, SYS_64:uselib)]	 = MAKE_UINT16(1, 1091),
	[SYSCALL_OR_NUM(135, SYS_personality)]	 = MAKE_UINT16(1, 1101),
	[SYSCALL_OR_NUM(136, SYS_ustat)]	 = MAKE_UINT16(2, 1113),
	[SYSCALL_OR_NUM(137, SYS_statfs)]	 = MAKE_UINT16(2, 1119),
	[SYSCALL_OR_NUM(138, SYS_fstatfs)]	 = MAKE_UINT16(2, 1126),
	[SYSCALL_OR_NUM(139, SYS_sysfs)]	 = MAKE_UINT16(3, 1134),
	[SYSCALL_OR_NUM(140, SYS_getpriority)]	 = MAKE_UINT16(2, 1140),
	[SYSCALL_OR_NUM(141, SYS_setpriority)]	 = MAKE_UINT16(3, 1152),
	[SYSCALL_OR_NUM(142, SYS_sched_setparam)]	 = MAKE_UINT16(0, 1164),
	[SYSCALL_OR_NUM(143, SYS_sched_getparam)]	 = MAKE_UINT16(2, 1179),
	[SYSCALL_OR_NUM(144, SYS_sched_setscheduler)]	 = MAKE_UINT16(3, 1194),
	[SYSCALL_OR_NUM(145, SYS_sched_getscheduler)]	 = MAKE_UINT16(1, 1213),
	[SYSCALL_OR_NUM(146, SYS_sched_get_priority_max)]	 = MAKE_UINT16(1, 1232),
	[SYSCALL_OR_NUM(147, SYS_sched_get_priority_min)]	 = MAKE_UINT16(1, 1255),
	[SYSCALL_OR_NUM(148, SYS_sched_rr_get_interval)]	 = MAKE_UINT16(2, 1278),
	[SYSCALL_OR_NUM(149, SYS_mlock)]	 = MAKE_UINT16(2, 1300),
	[SYSCALL_OR_NUM(150, SYS_munlock)]	 = MAKE_UINT16(2, 1306),
	[SYSCALL_OR_NUM(151, SYS_mlockall)]	 = MAKE_UINT16(1, 1314),
	[SYSCALL_OR_NUM(152, SYS_munlockall)]	 = MAKE_UINT16(0, 1323),
	[SYSCALL_OR_NUM(153, SYS_vhangup)]	 = MAKE_UINT16(0, 1334),
	[SYSCALL_OR_NUM(154, SYS_modify_ldt)]	 = MAKE_UINT16(3, 1342),
	[SYSCALL_OR_NUM(155, SYS_pivot_root)]	 = MAKE_UINT16(2, 1353),
	[SYSCALL_OR_NUM(156, SYS_64:_sysctl)]	 = MAKE_UINT16(1, 1364),
	[SYSCALL_OR_NUM(157, SYS_prctl)]	 = MAKE_UINT16(5, 1375),
	[SYSCALL_OR_NUM(158, SYS_arch_prctl)]	 = MAKE_UINT16(2, 1381),
	[SYSCALL_OR_NUM(159, SYS_adjtimex)]	 = MAKE_UINT16(1, 1392),
	[SYSCALL_OR_NUM(160, SYS_setrlimit)]	 = MAKE_UINT16(2, 1401),
	[SYSCALL_OR_NUM(161, SYS_chroot)]	 = MAKE_UINT16(1, 1411),
	[SYSCALL_OR_NUM(162, SYS_sync)]	 = MAKE_UINT16(0, 1418),
	[SYSCALL_OR_NUM(163, SYS_acct)]	 = MAKE_UINT16(1, 1423),
	[SYSCALL_OR_NUM(164, SYS_settimeofday)]	 = MAKE_UINT16(2, 1428),
	[SYSCALL_OR_NUM(165, SYS_mount)]	 = MAKE_UINT16(5, 1441),
	[SYSCALL_OR_NUM(166, SYS_umount)]	 = MAKE_UINT16(2, 1447),
	[SYSCALL_OR_NUM(167, SYS_swapon)]	 = MAKE_UINT16(2, 1454),
	[SYSCALL_OR_NUM(168, SYS_swapoff)]	 = MAKE_UINT16(1, 1461),
	[SYSCALL_OR_NUM(169, SYS_reboot)]	 = MAKE_UINT16(4, 1469),
	[SYSCALL_OR_NUM(170, SYS_sethostname)]	 = MAKE_UINT16(2, 1476),
	[SYSCALL_OR_NUM(171, SYS_setdomainname)]	 = MAKE_UINT16(2, 1488),
	[SYSCALL_OR_NUM(172, SYS_iopl)]	 = MAKE_UINT16(1, 1502),
	[SYSCALL_OR_NUM(173, SYS_ioperm)]	 = MAKE_UINT16(3, 1507),
	[SYSCALL_OR_NUM(174, SYS_64:create_module)]	 = MAKE_UINT16(2, 1514),
	[SYSCALL_OR_NUM(175, SYS_init_module)]	 = MAKE_UINT16(3, 1531),
	[SYSCALL_OR_NUM(176, SYS_delete_module)]	 = MAKE_UINT16(2, 1543),
	[SYSCALL_OR_NUM(177, SYS_64:get_kernel_syms)]	 = MAKE_UINT16(1, 1557),
	[SYSCALL_OR_NUM(178, SYS_64:query_module)]	 = MAKE_UINT16(5, 1576),
	[SYSCALL_OR_NUM(179, SYS_quotactl)]	 = MAKE_UINT16(4, 1592),
	[SYSCALL_OR_NUM(180, SYS_64:nfsservctl)]	 = MAKE_UINT16(3, 1601),
	[SYSCALL_OR_NUM(181, SYS_getpmsg)]	 = MAKE_UINT16(5, 1615),
	[SYSCALL_OR_NUM(182, SYS_putpmsg)]	 = MAKE_UINT16(5, 1623),
	[SYSCALL_OR_NUM(183, SYS_afs_syscall)]	 = MAKE_UINT16(5, 1631),
	[SYSCALL_OR_NUM(184, SYS_tuxcall)]	 = MAKE_UINT16(3, 1643),
	[SYSCALL_OR_NUM(185, SYS_security)]	 = MAKE_UINT16(3, 1651),
	[SYSCALL_OR_NUM(186, SYS_gettid)]	 = MAKE_UINT16(0, 1660),
	[SYSCALL_OR_NUM(187, SYS_readahead)]	 = MAKE_UINT16(4, 1667),
	[SYSCALL_OR_NUM(188, SYS_setxattr)]	 = MAKE_UINT16(5, 1677),
	[SYSCALL_OR_NUM(189, SYS_lsetxattr)]	 = MAKE_UINT16(5, 1686),
	[SYSCALL_OR_NUM(190, SYS_fsetxattr)]	 = MAKE_UINT16(5, 1696),
	[SYSCALL_OR_NUM(191, SYS_getxattr)]	 = MAKE_UINT16(4, 1706),
	[SYSCALL_OR_NUM(192, SYS_lgetxattr)]	 = MAKE_UINT16(4, 1715),
	[SYSCALL_OR_NUM(193, SYS_fgetxattr)]	 = MAKE_UINT16(4, 1725),
	[SYSCALL_OR_NUM(194, SYS_listxattr)]	 = MAKE_UINT16(3, 1735),
	[SYSCALL_OR_NUM(195, SYS_llistxattr)]	 = MAKE_UINT16(3, 1745),
	[SYSCALL_OR_NUM(196, SYS_flistxattr)]	 = MAKE_UINT16(3, 1756),
	[SYSCALL_OR_NUM(197, SYS_removexattr)]	 = MAKE_UINT16(2, 1767),
	[SYSCALL_OR_NUM(198, SYS_lremovexattr)]	 = MAKE_UINT16(2, 1779),
	[SYSCALL_OR_NUM(199, SYS_fremovexattr)]	 = MAKE_UINT16(2, 1792),
	[SYSCALL_OR_NUM(200, SYS_tkill)]	 = MAKE_UINT16(2, 1805),
	[SYSCALL_OR_NUM(201, SYS_time)]	 = MAKE_UINT16(1, 1811),
	[SYSCALL_OR_NUM(202, SYS_futex)]	 = MAKE_UINT16(6, 1816),
	[SYSCALL_OR_NUM(203, SYS_sched_setaffinity)]	 = MAKE_UINT16(3, 1822),
	[SYSCALL_OR_NUM(204, SYS_sched_getaffinity)]	 = MAKE_UINT16(3, 1840),
	[SYSCALL_OR_NUM(205, SYS_64:set_thread_area)]	 = MAKE_UINT16(1, 1858),
	[SYSCALL_OR_NUM(206, SYS_io_setup)]	 = MAKE_UINT16(2, 1877),
	[SYSCALL_OR_NUM(207, SYS_io_destroy)]	 = MAKE_UINT16(1, 1886),
	[SYSCALL_OR_NUM(208, SYS_io_getevents)]	 = MAKE_UINT16(5, 1897),
	[SYSCALL_OR_NUM(209, SYS_io_submit)]	 = MAKE_UINT16(3, 1910),
	[SYSCALL_OR_NUM(210, SYS_io_cancel)]	 = MAKE_UINT16(3, 1920),
	[SYSCALL_OR_NUM(211, SYS_64:get_thread_area)]	 = MAKE_UINT16(1, 1930),
	[SYSCALL_OR_NUM(212, SYS_lookup_dcookie)]	 = MAKE_UINT16(4, 1949),
	[SYSCALL_OR_NUM(213, SYS_epoll_create)]	 = MAKE_UINT16(1, 1964),
	[SYSCALL_OR_NUM(214, SYS_64:epoll_ctl_old)]	 = MAKE_UINT16(4, 1977),
	[SYSCALL_OR_NUM(215, SYS_64:epoll_wait_old)]	 = MAKE_UINT16(4, 1994),
	[SYSCALL_OR_NUM(216, SYS_remap_file_pages)]	 = MAKE_UINT16(5, 2012),
	[SYSCALL_OR_NUM(217, SYS_getdents64)]	 = MAKE_UINT16(3, 2029),
	[SYSCALL_OR_NUM(218, SYS_set_tid_address)]	 = MAKE_UINT16(1, 2040),
	[SYSCALL_OR_NUM(219, SYS_restart_syscall)]	 = MAKE_UINT16(0, 2056),
	[SYSCALL_OR_NUM(220, SYS_semtimedop)]	 = MAKE_UINT16(5, 2072),
	[SYSCALL_OR_NUM(221, SYS_fadvise64)]	 = MAKE_UINT16(4, 2083),
	[SYSCALL_OR_NUM(222, SYS_64:timer_create)]	 = MAKE_UINT16(3, 2093),
	[SYSCALL_OR_NUM(223, SYS_timer_settime)]	 = MAKE_UINT16(4, 2109),
	[SYSCALL_OR_NUM(224, SYS_timer_gettime)]	 = MAKE_UINT16(2, 2123),
	[SYSCALL_OR_NUM(225, SYS_timer_getoverrun)]	 = MAKE_UINT16(1, 2137),
	[SYSCALL_OR_NUM(226, SYS_timer_delete)]	 = MAKE_UINT16(1, 2154),
	[SYSCALL_OR_NUM(227, SYS_clock_settime)]	 = MAKE_UINT16(2, 2167),
	[SYSCALL_OR_NUM(228, SYS_clock_gettime)]	 = MAKE_UINT16(2, 2181),
	[SYSCALL_OR_NUM(229, SYS_clock_getres)]	 = MAKE_UINT16(2, 2195),
	[SYSCALL_OR_NUM(230, SYS_clock_nanosleep)]	 = MAKE_UINT16(4, 2208),
	[SYSCALL_OR_NUM(231, SYS_exit_group)]	 = MAKE_UINT16(1, 2224),
	[SYSCALL_OR_NUM(232, SYS_epoll_wait)]	 = MAKE_UINT16(4, 2235),
	[SYSCALL_OR_NUM(233, SYS_epoll_ctl)]	 = MAKE_UINT16(4, 2246),
	[SYSCALL_OR_NUM(234, SYS_tgkill)]	 = MAKE_UINT16(3, 2256),
	[SYSCALL_OR_NUM(235, SYS_utimes)]	 = MAKE_UINT16(2, 2263),
	[SYSCALL_OR_NUM(236, SYS_64:vserver)]	 = MAKE_UINT16(5, 2270),
	[SYSCALL_OR_NUM(237, SYS_mbind)]	 = MAKE_UINT16(6, 2281),
	[SYSCALL_OR_NUM(238, SYS_set_mempolicy)]	 = MAKE_UINT16(3, 2287),
	[SYSCALL_OR_NUM(239, SYS_get_mempolicy)]	 = MAKE_UINT16(5, 2301),
	[SYSCALL_OR_NUM(240, SYS_mq_open)]	 = MAKE_UINT16(4, 2315),
	[SYSCALL_OR_NUM(241, SYS_mq_unlink)]	 = MAKE_UINT16(1, 2323),
	[SYSCALL_OR_NUM(242, SYS_mq_timedsend)]	 = MAKE_UINT16(5, 2333),
	[SYSCALL_OR_NUM(243, SYS_mq_timedreceive)]	 = MAKE_UINT16(5, 2346),
	[SYSCALL_OR_NUM(244, SYS_64:mq_notify)]	 = MAKE_UINT16(2, 2362),
	[SYSCALL_OR_NUM(245, SYS_mq_getsetattr)]	 = MAKE_UINT16(3, 2375),
	[SYSCALL_OR_NUM(246, SYS_64:kexec_load)]	 = MAKE_UINT16(4, 2389),
	[SYSCALL_OR_NUM(247, SYS_64:waitid)]	 = MAKE_UINT16(5, 2403),
	[SYSCALL_OR_NUM(248, SYS_add_key)]	 = MAKE_UINT16(5, 2413),
	[SYSCALL_OR_NUM(249, SYS_request_key)]	 = MAKE_UINT16(4, 2421),
	[SYSCALL_OR_NUM(250, SYS_keyctl)]	 = MAKE_UINT16(5, 2433),
	[SYSCALL_OR_NUM(251, SYS_ioprio_set)]	 = MAKE_UINT16(3, 2440),
	[SYSCALL_OR_NUM(252, SYS_ioprio_get)]	 = MAKE_UINT16(2, 2451),
	[SYSCALL_OR_NUM(253, SYS_inotify_init)]	 = MAKE_UINT16(0, 2462),
	[SYSCALL_OR_NUM(254, SYS_inotify_add_watch)]	 = MAKE_UINT16(3, 2475),
	[SYSCALL_OR_NUM(255, SYS_inotify_rm_watch)]	 = MAKE_UINT16(2, 2493),
	[SYSCALL_OR_NUM(256, SYS_migrate_pages)]	 = MAKE_UINT16(4, 2510),
	[SYSCALL_OR_NUM(257, SYS_openat)]	 = MAKE_UINT16(4, 2524),
	[SYSCALL_OR_NUM(258, SYS_mkdirat)]	 = MAKE_UINT16(3, 2531),
	[SYSCALL_OR_NUM(259, SYS_mknodat)]	 = MAKE_UINT16(4, 2539),
	[SYSCALL_OR_NUM(260, SYS_fchownat)]	 = MAKE_UINT16(5, 2547),
	[SYSCALL_OR_NUM(261, SYS_futimesat)]	 = MAKE_UINT16(3, 2556),
	[SYSCALL_OR_NUM(262, SYS_newfstatat)]	 = MAKE_UINT16(4, 2566),
	[SYSCALL_OR_NUM(263, SYS_unlinkat)]	 = MAKE_UINT16(3, 2577),
	[SYSCALL_OR_NUM(264, SYS_renameat)]	 = MAKE_UINT16(4, 2586),
	[SYSCALL_OR_NUM(265, SYS_linkat)]	 = MAKE_UINT16(5, 2595),
	[SYSCALL_OR_NUM(266, SYS_symlinkat)]	 = MAKE_UINT16(3, 2602),
	[SYSCALL_OR_NUM(267, SYS_readlinkat)]	 = MAKE_UINT16(4, 2612),
	[SYSCALL_OR_NUM(268, SYS_fchmodat)]	 = MAKE_UINT16(3, 2623),
	[SYSCALL_OR_NUM(269, SYS_faccessat)]	 = MAKE_UINT16(3, 2632),
	[SYSCALL_OR_NUM(270, SYS_pselect6)]	 = MAKE_UINT16(6, 2642),
	[SYSCALL_OR_NUM(271, SYS_ppoll)]	 = MAKE_UINT16(5, 2651),
	[SYSCALL_OR_NUM(272, SYS_unshare)]	 = MAKE_UINT16(1, 2657),
	[SYSCALL_OR_NUM(273, SYS_64:set_robust_list)]	 = MAKE_UINT16(2, 2665),
	[SYSCALL_OR_NUM(274, SYS_64:get_robust_list)]	 = MAKE_UINT16(3, 2684),
	[SYSCALL_OR_NUM(275, SYS_splice)]	 = MAKE_UINT16(6, 2703),
	[SYSCALL_OR_NUM(276, SYS_tee)]	 = MAKE_UINT16(4, 2710),
	[SYSCALL_OR_NUM(277, SYS_sync_file_range)]	 = MAKE_UINT16(4, 2714),
	[SYSCALL_OR_NUM(278, SYS_64:vmsplice)]	 = MAKE_UINT16(4, 2730),
	[SYSCALL_OR_NUM(279, SYS_64:move_pages)]	 = MAKE_UINT16(6, 2742),
	[SYSCALL_OR_NUM(280, SYS_utimensat)]	 = MAKE_UINT16(4, 2756),
	[SYSCALL_OR_NUM(281, SYS_epoll_pwait)]	 = MAKE_UINT16(6, 2766),
	[SYSCALL_OR_NUM(282, SYS_signalfd)]	 = MAKE_UINT16(3, 2778),
	[SYSCALL_OR_NUM(283, SYS_timerfd_create)]	 = MAKE_UINT16(2, 2787),
	[SYSCALL_OR_NUM(284, SYS_eventfd)]	 = MAKE_UINT16(1, 2802),
	[SYSCALL_OR_NUM(285, SYS_fallocate)]	 = MAKE_UINT16(6, 2810),
	[SYSCALL_OR_NUM(286, SYS_timerfd_settime)]	 = MAKE_UINT16(4, 2820),
	[SYSCALL_OR_NUM(287, SYS_timerfd_gettime)]	 = MAKE_UINT16(2, 2836),
	[SYSCALL_OR_NUM(288, SYS_accept4)]	 = MAKE_UINT16(4, 2852),
	[SYSCALL_OR_NUM(289, SYS_signalfd4)]	 = MAKE_UINT16(4, 2860),
	[SYSCALL_OR_NUM(290, SYS_eventfd2)]	 = MAKE_UINT16(2, 2870),
	[SYSCALL_OR_NUM(291, SYS_epoll_create1)]	 = MAKE_UINT16(1, 2879),
	[SYSCALL_OR_NUM(292, SYS_dup3)]	 = MAKE_UINT16(3, 2893),
	[SYSCALL_OR_NUM(293, SYS_pipe2)]	 = MAKE_UINT16(2, 2898),
	[SYSCALL_OR_NUM(294, SYS_inotify_init1)]	 = MAKE_UINT16(1, 2904),
	[SYSCALL_OR_NUM(295, SYS_64:preadv)]	 = MAKE_UINT16(5, 2918),
	[SYSCALL_OR_NUM(296, SYS_64:pwritev)]	 = MAKE_UINT16(5, 2928),
	[SYSCALL_OR_NUM(297, SYS_64:rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 2939),
	[SYSCALL_OR_NUM(298, SYS_perf_event_open)]	 = MAKE_UINT16(5, 2960),
	[SYSCALL_OR_NUM(299, SYS_64:recvmmsg)]	 = MAKE_UINT16(5, 2976),
	[SYSCALL_OR_NUM(300, SYS_fanotify_init)]	 = MAKE_UINT16(2, 2988),
	[SYSCALL_OR_NUM(301, SYS_fanotify_mark)]	 = MAKE_UINT16(5, 3002),
	[SYSCALL_OR_NUM(302, SYS_prlimit64)]	 = MAKE_UINT16(4, 3016),
	[SYSCALL_OR_NUM(303, SYS_name_to_handle_at)]	 = MAKE_UINT16(5, 3026),
	[SYSCALL_OR_NUM(304, SYS_open_by_handle_at)]	 = MAKE_UINT16(3, 3044),
	[SYSCALL_OR_NUM(305, SYS_clock_adjtime)]	 = MAKE_UINT16(2, 3062),
	[SYSCALL_OR_NUM(306, SYS_syncfs)]	 = MAKE_UINT16(1, 3076),
	[SYSCALL_OR_NUM(307, SYS_64:sendmmsg)]	 = MAKE_UINT16(4, 3083),
	[SYSCALL_OR_NUM(308, SYS_setns)]	 = MAKE_UINT16(2, 3095),
	[SYSCALL_OR_NUM(309, SYS_getcpu)]	 = MAKE_UINT16(3, 3101),
	[SYSCALL_OR_NUM(310, SYS_64:process_vm_readv)]	 = MAKE_UINT16(6, 3108),
	[SYSCALL_OR_NUM(311, SYS_64:process_vm_writev)]	 = MAKE_UINT16(6, 3128),
	[SYSCALL_OR_NUM(512, SYS_rt_sigaction)]	 = MAKE_UINT16(4, 3149),
	[SYSCALL_OR_NUM(513, SYS_rt_sigreturn)]	 = MAKE_UINT16(0, 3162),
	[SYSCALL_OR_NUM(514, SYS_ioctl)]	 = MAKE_UINT16(3, 3175),
	[SYSCALL_OR_NUM(515, SYS_readv)]	 = MAKE_UINT16(3, 3181),
	[SYSCALL_OR_NUM(516, SYS_writev)]	 = MAKE_UINT16(3, 3187),
	[SYSCALL_OR_NUM(517, SYS_recvfrom)]	 = MAKE_UINT16(6, 3194),
	[SYSCALL_OR_NUM(518, SYS_sendmsg)]	 = MAKE_UINT16(3, 3203),
	[SYSCALL_OR_NUM(519, SYS_recvmsg)]	 = MAKE_UINT16(5, 3211),
	[SYSCALL_OR_NUM(520, SYS_execve)]	 = MAKE_UINT16(3, 3219),
	[SYSCALL_OR_NUM(521, SYS_ptrace)]	 = MAKE_UINT16(4, 3226),
	[SYSCALL_OR_NUM(522, SYS_rt_sigpending)]	 = MAKE_UINT16(2, 3233),
	[SYSCALL_OR_NUM(523, SYS_rt_sigtimedwait)]	 = MAKE_UINT16(4, 3247),
	[SYSCALL_OR_NUM(524, SYS_rt_sigqueueinfo)]	 = MAKE_UINT16(3, 3263),
	[SYSCALL_OR_NUM(525, SYS_sigaltstack)]	 = MAKE_UINT16(2, 3279),
	[SYSCALL_OR_NUM(526, SYS_timer_create)]	 = MAKE_UINT16(3, 3291),
	[SYSCALL_OR_NUM(527, SYS_mq_notify)]	 = MAKE_UINT16(2, 3304),
	[SYSCALL_OR_NUM(528, SYS_kexec_load)]	 = MAKE_UINT16(4, 3314),
	[SYSCALL_OR_NUM(529, SYS_waitid)]	 = MAKE_UINT16(5, 3325),
	[SYSCALL_OR_NUM(530, SYS_set_robust_list)]	 = MAKE_UINT16(2, 3332),
	[SYSCALL_OR_NUM(531, SYS_get_robust_list)]	 = MAKE_UINT16(3, 3348),
	[SYSCALL_OR_NUM(532, SYS_vmsplice)]	 = MAKE_UINT16(4, 3364),
	[SYSCALL_OR_NUM(533, SYS_move_pages)]	 = MAKE_UINT16(6, 3373),
	[SYSCALL_OR_NUM(534, SYS_preadv)]	 = MAKE_UINT16(5, 3384),
	[SYSCALL_OR_NUM(535, SYS_pwritev)]	 = MAKE_UINT16(5, 3391),
	[SYSCALL_OR_NUM(536, SYS_rt_tgsigqueueinfo)]	 = MAKE_UINT16(4, 3399),
	[SYSCALL_OR_NUM(537, SYS_recvmmsg)]	 = MAKE_UINT16(5, 3417),
	[SYSCALL_OR_NUM(538, SYS_sendmmsg)]	 = MAKE_UINT16(4, 3426),
	[SYSCALL_OR_NUM(539, SYS_process_vm_readv)]	 = MAKE_UINT16(6, 3435),
	[SYSCALL_OR_NUM(540, SYS_process_vm_writev)]	 = MAKE_UINT16(6, 3452),
	[SYSCALL_OR_NUM(541, SYS_setsockopt)]	 = MAKE_UINT16(5, 3470),
	[SYSCALL_OR_NUM(542, SYS_getsockopt)]	 = MAKE_UINT16(5, 3481),
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
"64:rt_sigaction\0"
"rt_sigprocmask\0"
"64:rt_sigreturn\0"
"64:ioctl\0"
"pread\0"
"pwrite\0"
"64:readv\0"
"64:writev\0"
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
"64:recvfrom\0"
"64:sendmsg\0"
"64:recvmsg\0"
"shutdown\0"
"bind\0"
"listen\0"
"getsockname\0"
"getpeername\0"
"socketpair\0"
"64:setsockopt\0"
"64:getsockopt\0"
"clone\0"
"fork\0"
"vfork\0"
"64:execve\0"
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
"64:ptrace\0"
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
"64:rt_sigpending\0"
"64:rt_sigtimedwait\0"
"64:rt_sigqueueinfo\0"
"rt_sigsuspend\0"
"64:sigaltstack\0"
"utime\0"
"mknod\0"
"64:uselib\0"
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
"64:_sysctl\0"
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
"64:create_module\0"
"init_module\0"
"delete_module\0"
"64:get_kernel_syms\0"
"64:query_module\0"
"quotactl\0"
"64:nfsservctl\0"
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
"64:set_thread_area\0"
"io_setup\0"
"io_destroy\0"
"io_getevents\0"
"io_submit\0"
"io_cancel\0"
"64:get_thread_area\0"
"lookup_dcookie\0"
"epoll_create\0"
"64:epoll_ctl_old\0"
"64:epoll_wait_old\0"
"remap_file_pages\0"
"getdents64\0"
"set_tid_address\0"
"restart_syscall\0"
"semtimedop\0"
"fadvise64\0"
"64:timer_create\0"
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
"64:vserver\0"
"mbind\0"
"set_mempolicy\0"
"get_mempolicy\0"
"mq_open\0"
"mq_unlink\0"
"mq_timedsend\0"
"mq_timedreceive\0"
"64:mq_notify\0"
"mq_getsetattr\0"
"64:kexec_load\0"
"64:waitid\0"
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
"64:set_robust_list\0"
"64:get_robust_list\0"
"splice\0"
"tee\0"
"sync_file_range\0"
"64:vmsplice\0"
"64:move_pages\0"
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
"64:preadv\0"
"64:pwritev\0"
"64:rt_tgsigqueueinfo\0"
"perf_event_open\0"
"64:recvmmsg\0"
"fanotify_init\0"
"fanotify_mark\0"
"prlimit64\0"
"name_to_handle_at\0"
"open_by_handle_at\0"
"clock_adjtime\0"
"syncfs\0"
"64:sendmmsg\0"
"setns\0"
"getcpu\0"
"64:process_vm_readv\0"
"64:process_vm_writev\0"
"rt_sigaction\0"
"rt_sigreturn\0"
"ioctl\0"
"readv\0"
"writev\0"
"recvfrom\0"
"sendmsg\0"
"recvmsg\0"
"execve\0"
"ptrace\0"
"rt_sigpending\0"
"rt_sigtimedwait\0"
"rt_sigqueueinfo\0"
"sigaltstack\0"
"timer_create\0"
"mq_notify\0"
"kexec_load\0"
"waitid\0"
"set_robust_list\0"
"get_robust_list\0"
"vmsplice\0"
"move_pages\0"
"preadv\0"
"pwritev\0"
"rt_tgsigqueueinfo\0"
"recvmmsg\0"
"sendmmsg\0"
"process_vm_readv\0"
"process_vm_writev\0"
"setsockopt\0"
"getsockopt\0"
"";
/*
longest string: 22
total concatenated string length: 3491
pointer overhead: 2744
strings + overhead: 6235
total size aligned to max strlen 7889
*/
