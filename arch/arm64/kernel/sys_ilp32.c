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
#define sys_rt_sigreturn        sys_rt_sigreturn_wrapper
#define sys_rt_sigsuspend       compat_sys_rt_sigsuspend
#define sys_rt_sigaction        compat_sys_rt_sigaction
#define sys_rt_sigprocmask      compat_sys_rt_sigprocmask
#define sys_rt_sigpending       compat_sys_rt_sigpending
#define sys_rt_sigtimedwait     compat_sys_rt_sigtimedwait
#define sys_rt_sigqueueinfo     compat_sys_rt_sigqueueinfo
#define sys_rt_sigpending       compat_sys_rt_sigpending

/* Using Compat syscalls where necessary */
#define sys_ioctl		compat_sys_ioctl
#define sys_fcntl		compat_sys_fcntl
/* iovec */
#define sys_readv		compat_sys_readv
#define sys_writev		compat_sys_writev
#define sys_preadv		compat_sys_preadv64
#define sys_pwritev		compat_sys_pwritev64
#define sys_vmsplice		compat_sys_vmsplice
/* robust_list_head */
#define sys_set_robust_list	compat_sys_set_robust_list
#define sys_get_robust_list	compat_sys_get_robust_list

/* kexec_segment */
#define sys_kexec_load		compat_sys_kexec_load

/* Ptrace has some structures which are different between ILP32 and LP64 */
#define sys_ptrace		compat_sys_ptrace

/* struct msghdr */
#define sys_recvfrom		compat_sys_recvfrom
#define sys_recvmmsg		compat_sys_recvmmsg
#define sys_sendmmsg		compat_sys_sendmmsg
#define sys_sendmsg		compat_sys_sendmsg
#define sys_recvmsg		compat_sys_recvmsg
#define sys_msgsnd		compat_sys_msgsnd
#define sys_msgrcv		compat_sys_msgrcv

#define sys_setsockopt		compat_sys_setsockopt
#define sys_getsockopt		compat_sys_getsockopt

/* Array of pointers */
#define sys_execve		compat_sys_execve
#define sys_move_pages		compat_sys_move_pages

/* iovec */
#define sys_process_vm_readv	compat_sys_process_vm_readv
#define sys_process_vm_writev	compat_sys_process_vm_writev

/* Pointer in struct */
#define sys_mount               compat_sys_mount

/* NUMA */
/* unsigned long bitmaps */
#define sys_get_mempolicy       compat_sys_get_mempolicy
#define sys_set_mempolicy       compat_sys_set_mempolicy
#define sys_mbind               compat_sys_mbind
/* array of pointers */
/* unsigned long bitmaps */
#define sys_migrate_pages       compat_sys_migrate_pages

/* Scheduler */
/* unsigned long bitmaps */
#define sys_sched_setaffinity   compat_sys_sched_setaffinity
#define sys_sched_getaffinity   compat_sys_sched_getaffinity

/* iov usage */
#define sys_keyctl              compat_sys_keyctl

/* aio */
/* Pointer to Pointer  */
#define sys_io_setup		compat_sys_io_setup
/* Array of pointers */
#define sys_io_submit           compat_sys_io_submit

#define sys_nanosleep           compat_sys_nanosleep

#define sys_lseek               sys_llseek

#define sys_setitimer           compat_sys_setitimer
#define sys_getitimer           compat_sys_getitimer

#define sys_gettimeofday        compat_sys_gettimeofday
#define sys_settimeofday        compat_sys_settimeofday
#define sys_adjtimex            compat_sys_adjtimex

#define sys_clock_gettime       compat_sys_clock_gettime
#define sys_clock_settime       compat_sys_clock_settime

#define sys_timerfd_gettime     compat_sys_timerfd_gettime
#define sys_timerfd_settime     compat_sys_timerfd_settime
#define sys_utimensat           compat_sys_utimensat

#define sys_getrlimit           compat_sys_getrlimit
#define sys_setrlimit           compat_sys_setrlimit
#define sys_getrusage           compat_sys_getrusage

#define sys_futex               compat_sys_futex
#define sys_get_robust_list     compat_sys_get_robust_list
#define sys_set_robust_list     compat_sys_set_robust_list

#define sys_pselect6            compat_sys_pselect6
#define sys_ppoll               compat_sys_ppoll

#define sys_times               compat_sys_times

asmlinkage long compat_sys_mmap2_wrapper(void);
#define sys_mmap                compat_sys_mmap2_wrapper

asmlinkage long compat_sys_fstatfs64_wrapper(void);
#define sys_fstatfs            compat_sys_fstatfs64_wrapper
asmlinkage long compat_sys_statfs64_wrapper(void);
#define sys_statfs             compat_sys_statfs64_wrapper

/* IPC_64 */
asmlinkage long ilp32_sys_msgctl(int first, int second, void __user *uptr)
{
	return compat_sys_msgctl(first, second | IPC_64, uptr);
}
#define sys_msgctl		ilp32_sys_msgctl

asmlinkage long ilp32_sys_shmctl(int first, int second, void __user *uptr)
{
	return compat_sys_shmctl(first, second | IPC_64, uptr);
}
#define sys_shmctl		ilp32_sys_shmctl

asmlinkage long ilp32_sys_semctl(int first, int second, int third, int arg)
{
	return compat_sys_semctl(first, second, third | IPC_64, arg);
}
#define sys_semctl	ilp32_sys_semctl

/* We need to make sure the pointer gets copied correctly. */
asmlinkage long ilp32_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *u_notification)
{
	struct sigevent __user *p = NULL;
	if (u_notification) {
		struct sigevent n;
		p = compat_alloc_user_space(sizeof(*p));
		if (copy_from_user(&n, u_notification, sizeof(*p)))
			return -EFAULT;
		if (n.sigev_notify == SIGEV_THREAD)
			n.sigev_value.sival_ptr = compat_ptr((uintptr_t)n.sigev_value.sival_ptr);
		if (copy_to_user(p, &n, sizeof(*p)))
			return -EFAULT;
	}
	return sys_mq_notify(mqdes, p);
}

/* sigevent contains sigval_t which is now 64bit always
   but need special handling due to padding for SIGEV_THREAD.  */
#define sys_mq_notify		ilp32_sys_mq_notify

/* sigaltstack needs some special handling as the
   padding for stack_t might not be non-zero. */
long ilp32_sys_sigaltstack(const stack_t __user *uss_ptr,
			   stack_t __user *uoss_ptr)
{
	stack_t uss, uoss;
	int ret;
	mm_segment_t seg;

	if (uss_ptr) {
		if (!access_ok(VERIFY_READ, uss_ptr, sizeof(*uss_ptr)))
			return -EFAULT;
		if (__get_user(uss.ss_sp, &uss_ptr->ss_sp) |
			__get_user(uss.ss_flags, &uss_ptr->ss_flags) |
			__get_user(uss.ss_size, &uss_ptr->ss_size))
			return -EFAULT;
		/* Zero extend the sp address and the size. */
		uss.ss_sp = (void *)(uintptr_t)(unsigned int)(uintptr_t)uss.ss_sp;
		uss.ss_size = (size_t)(unsigned int)uss.ss_size;
	}
	seg = get_fs();
	set_fs(KERNEL_DS);
	/* Note we need to use uoss as we have changed the segment to the
	   kernel one so passing an user one around is wrong. */
	ret = sys_sigaltstack((stack_t __force __user *) (uss_ptr ? &uss : NULL),
			      (stack_t __force __user *) &uoss);
	set_fs(seg);
	if (ret >= 0 && uoss_ptr)  {
		if (!access_ok(VERIFY_WRITE, uoss_ptr, sizeof(stack_t)) ||
		    __put_user(uoss.ss_sp, &uoss_ptr->ss_sp) ||
		    __put_user(uoss.ss_flags, &uoss_ptr->ss_flags) ||
		    __put_user(uoss.ss_size, &uoss_ptr->ss_size))
			ret = -EFAULT;
	}
	return ret;
}

/* sigaltstack needs some special handling as the padding
   for stack_t might not be non-zero. */
#define sys_sigaltstack		ilp32_sys_sigaltstack

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

static long cp_ilp32_stat(struct kstat *stat,
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

asmlinkage long ilp32_sys_stat(const char __user *filename,
			       struct ilp32_stat __user *statbuf)
{
	struct kstat stat;
	int error = vfs_stat(filename, &stat);

	if (!error)
		error = cp_ilp32_stat(&stat, statbuf);
	return error;
}
#define sys_newstat		ilp32_sys_stat

asmlinkage long ilp32_sys_lstat(const char __user *filename,
				struct ilp32_stat __user *statbuf)
{
	struct kstat stat;
	int error = vfs_lstat(filename, &stat);

	if (!error)
		error = cp_ilp32_stat(&stat, statbuf);
	return error;
}
#define sys_newlstat		ilp32_sys_lstat

asmlinkage long ilp32_sys_fstat(unsigned int fd,
				struct ilp32_stat __user *statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_ilp32_stat(&stat, statbuf);
	return error;
}
#define sys_newfstat		ilp32_sys_fstat

asmlinkage long ilp32_sys_fstatat(unsigned int dfd,
				  const char __user *filename,
				  struct ilp32_stat __user *statbuf, int flag)
{
	struct kstat stat;
	int error = vfs_fstatat(dfd, filename, &stat, flag);

	if (!error)
		error = cp_ilp32_stat(&stat, statbuf);
	return error;
}
#define sys_newfstatat		ilp32_sys_fstatat

#include <asm/syscall.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_ilp32_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void *sys_call_ilp32_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};
