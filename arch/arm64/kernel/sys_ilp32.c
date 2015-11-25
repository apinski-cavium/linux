/*
 * AArch64- ILP32 specific system calls implementation
 *
 * Copyright (C) 2015 Cavium Inc.
 * Author: Andrew Pinski <apinski@cavium.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/msg.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/compat.h>

/*
 * Wrappers to pass the pt_regs argument.
 */
asmlinkage long sys_rt_sigreturn_wrapper(void);
#define compat_sys_rt_sigreturn        sys_rt_sigreturn_wrapper

/* Using non-compat syscalls where necessary */
#define compat_sys_fadvise64_64        sys_fadvise64_64
#define compat_sys_fallocate           sys_fallocate
#define compat_sys_ftruncate64         sys_ftruncate
#define compat_sys_pread64             sys_pread64
#define compat_sys_pwrite64            sys_pwrite64
#define compat_sys_readahead           sys_readahead
#define compat_sys_rt_sigaction        sys_rt_sigaction
#define compat_sys_shmat               sys_shmat
#define compat_sys_sync_file_range     sys_sync_file_range
#define compat_sys_truncate64          sys_truncate
#define compat_sys_sigaltstack         sys_sigaltstack

#define compat_sys_io_getevents        sys_io_getevents
#define compat_sys_lookup_dcookie      sys_lookup_dcookie
#define compat_sys_epoll_pwait         sys_epoll_pwait
#define compat_sys_fcntl64             compat_sys_fcntl
#define compat_sys_preadv              compat_sys_preadv64
#define compat_sys_signalfd4           sys_signalfd4

#define compat_sys_rt_sigsuspend       sys_rt_sigsuspend
#define compat_sys_rt_sigprocmask      sys_rt_sigprocmask
#define compat_sys_rt_sigpending       sys_rt_sigpending
#define compat_sys_rt_sigqueueinfo     sys_rt_sigqueueinfo
#define compat_sys_semtimedop          sys_semtimedop
#define compat_sys_rt_tgsigqueueinfo   sys_rt_tgsigqueueinfo

#define compat_sys_timer_create        sys_timer_create
#define compat_sys_timer_gettime       sys_timer_gettime
#define compat_sys_timer_settime       sys_timer_settime
#define compat_sys_rt_sigtimedwait     sys_rt_sigtimedwait

#define compat_sys_mq_open             sys_mq_open
#define compat_sys_mq_timedsend        sys_mq_timedsend
#define compat_sys_mq_timedreceive     sys_mq_timedreceive
#define compat_sys_mq_getsetattr       sys_mq_getsetattr
#define compat_sys_mq_open             sys_mq_open

#define compat_sys_open_by_handle_at   sys_open_by_handle_at
#define compat_sys_clock_adjtime       sys_clock_adjtime

#define compat_sys_openat              sys_openat
#define compat_sys_getdents64          sys_getdents64
#define compat_sys_waitid              sys_waitid
#define compat_sys_timer_settime       sys_timer_settime
#define compat_sys_sched_rr_get_interval sys_sched_rr_get_interval
#define compat_sys_execveat            sys_execveat

#define compat_sys_mq_notify           sys_mq_notify
#define compat_sys_clock_nanosleep     sys_clock_nanosleep
#define compat_sys_clock_getres        sys_clock_getres

#define sys_llseek                     sys_lseek

asmlinkage long compat_sys_mmap2_wrapper(void);
#define sys_mmap2                      compat_sys_mmap2_wrapper

asmlinkage long compat_sys_fstatfs64_wrapper(void);
#define compat_sys_fstatfs64    compat_sys_fstatfs64_wrapper
asmlinkage long compat_sys_statfs64_wrapper(void);
#define compat_sys_statfs64             compat_sys_statfs64_wrapper

#define compat_sys_pwritev	       compat_sys_pwritev64

/* IPC_64 */
asmlinkage long ilp32_sys_msgctl(int first, int second, void __user *uptr)
{
	return compat_sys_msgctl(first, second | IPC_64, uptr);
}
#define compat_sys_msgctl		ilp32_sys_msgctl

asmlinkage long ilp32_sys_shmctl(int first, int second, void __user *uptr)
{
	return compat_sys_shmctl(first, second | IPC_64, uptr);
}
#define compat_sys_shmctl		ilp32_sys_shmctl

asmlinkage long ilp32_sys_semctl(int first, int second, int third, int arg)
{
	return compat_sys_semctl(first, second, third | IPC_64, arg);
}
#define compat_sys_semctl	ilp32_sys_semctl

struct ilp32_stat {
	unsigned long st_dev;

	unsigned long st_ino;

	unsigned int st_mode;
	unsigned int st_nlink;

	unsigned int st_uid;
	unsigned int st_gid;

	unsigned long st_rdev;
	unsigned long __st_rdev_pad;

	long st_size;

	unsigned int st_blksize;
	unsigned int __st_blksize_pad;

	unsigned long st_blocks;

	unsigned int st_atime;
	unsigned int st_atime_nsec;

	unsigned int st_mtime;
	unsigned int st_mtime_nsec;

	unsigned int st_ctime;
	unsigned int st_ctime_nsec;

	unsigned int __unused[2];
};

static long ilp32_cp_stat(struct kstat *stat,
			  struct ilp32_stat __user *statbuf)
{
	struct ilp32_stat tmp = {
		.st_dev = huge_encode_dev(stat->dev),
		.st_ino = stat->ino,
		.st_mode = stat->mode,
		.st_nlink = stat->nlink,
		.st_uid = from_kuid_munged(current_user_ns(), stat->uid),
		.st_gid = from_kgid_munged(current_user_ns(), stat->gid),
		.st_rdev = huge_encode_dev(stat->rdev),
		.__st_rdev_pad = 0,
		.st_size = stat->size,
		.st_blksize = stat->blksize,
		.__st_blksize_pad = 0,
		.st_blocks = stat->blocks,
		.st_atime = stat->atime.tv_sec,
		.st_atime_nsec = stat->atime.tv_nsec,
		.st_mtime = stat->mtime.tv_sec,
		.st_mtime_nsec = stat->mtime.tv_nsec,
		.st_ctime = stat->ctime.tv_sec,
		.st_ctime_nsec = stat->ctime.tv_nsec,
		.__unused = { 0, 0 }
	};

	return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

asmlinkage long ilp32_sys_fstat64(unsigned int fd,
				struct ilp32_stat __user *statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = ilp32_cp_stat(&stat, statbuf);
	return error;
}
#define sys_fstat64		ilp32_sys_fstat64

asmlinkage long ilp32_sys_fstatat64(unsigned int dfd,
				  const char __user *filename,
				  struct ilp32_stat __user *statbuf, int flag)
{
	struct kstat stat;
	int error = vfs_fstatat(dfd, filename, &stat, flag);

	if (!error)
		error = ilp32_cp_stat(&stat, statbuf);
	return error;
}
#define sys_fstatat64		ilp32_sys_fstatat64

#include <asm/syscall.h>

#undef __SYSCALL
#undef __SC_COMP
#undef __SC_3264
#undef __SC_COMP_3264

#define __SYSCALL_COMPAT
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_ilp32_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void *sys_call_ilp32_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};
