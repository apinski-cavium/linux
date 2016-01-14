#ifndef __COMPAT_WRAPPER
#define __COMPAT_WRAPPER

#include <asm/compat_wrapper.h>

#define COMPAT_SYSCALL_WRAP1(name, ...) \
	COMPAT_SYSCALL_WRAPx(1, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_WRAP2(name, ...) \
	COMPAT_SYSCALL_WRAPx(2, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_WRAP3(name, ...) \
	COMPAT_SYSCALL_WRAPx(3, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_WRAP4(name, ...) \
	COMPAT_SYSCALL_WRAPx(4, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_WRAP5(name, ...) \
	COMPAT_SYSCALL_WRAPx(5, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_WRAP6(name, ...) \
	COMPAT_SYSCALL_WRAPx(6, _##name, __VA_ARGS__)

#ifndef __SC_COMPAT_TYPE
#define __SC_COMPAT_TYPE(t, a) \
	__typeof(__builtin_choose_expr(sizeof(t) > 4, 0L, (t)0)) a
#endif

#ifndef __SC_COMPAT_CAST
#define __SC_COMPAT_CAST(t, a)	((t) ((t)(-1) < 0 ? (s64)(s32)(a) : (u64)(u32)(a)))
#endif
/*
 * The COMPAT_SYSCALL_WRAP macro generates system call wrappers to be used by
 * compat tasks. These wrappers will only be used for system calls where only
 * the system call arguments need sign or zero extension or zeroing of the upper
 * 33 bits of pointers.
 * Note: since the wrapper function will afterwards call a system call which
 * again performs zero and sign extension for all system call arguments with
 * a size of less than eight bytes, these compat wrappers only touch those
 * system call arguments with a size of eight bytes ((unsigned) long and
 * pointers). Zero and sign extension for e.g. int parameters will be done by
 * the regular system call wrappers.
 */
#ifndef COMPAT_SYSCALL_WRAPx
#define COMPAT_SYSCALL_WRAPx(x, name, ...)						\
asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));				\
asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))			\
		__attribute__((alias(__stringify(compat_SyS##name))));			\
asmlinkage long notrace compat_SyS##name(__MAP(x,__SC_COMPAT_TYPE,__VA_ARGS__));	\
asmlinkage long notrace compat_SyS##name(__MAP(x,__SC_COMPAT_TYPE,__VA_ARGS__))		\
{											\
	return sys##name(__MAP(x,__SC_COMPAT_CAST,__VA_ARGS__));			\
}
#endif

asmlinkage long compat_sys_creat(const char __user *pathname, umode_t mode);
asmlinkage long compat_sys_link(const char __user *oldname,
				const char __user *newname);
asmlinkage long compat_sys_chdir(const char __user *filename);
asmlinkage long compat_sys_mknod(const char __user *filename, umode_t mode,
				unsigned dev);
asmlinkage long compat_sys_chmod(const char __user *filename, umode_t mode);
asmlinkage long compat_sys_oldumount(char __user *name);
asmlinkage long compat_sys_access(const char __user *filename, int mode);
asmlinkage long compat_sys_rename(const char __user *oldname,
				const char __user *newname);
asmlinkage long compat_sys_mkdir(const char __user *pathname, umode_t mode);
asmlinkage long compat_sys_rmdir(const char __user *pathname);
asmlinkage long compat_sys_pipe(int __user *fildes);
asmlinkage long compat_sys_brk(unsigned long brk);
asmlinkage long compat_sys_signal(int sig, __sighandler_t handler);
asmlinkage long compat_sys_acct(const char __user *name);
asmlinkage long compat_sys_umount(char __user *name, int flags);
asmlinkage long compat_sys_chroot(const char __user *filename);

#ifdef CONFIG_OLD_SIGSUSPEND
asmlinkage long compat_sys_sigsuspend(old_sigset_t mask);
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
asmlinkage long compat_sys_sigsuspend(int unused1, int unused2, old_sigset_t mask);
#endif

asmlinkage long compat_sys_sethostname(char __user *name, int len);
asmlinkage long compat_sys_symlink(const char __user *old, const char __user *new);
asmlinkage long compat_sys_readlink(const char __user *path,
				char __user *buf, int bufsiz);
asmlinkage long compat_sys_uselib(const char __user *library);
asmlinkage long compat_sys_swapon(const char __user *specialfile, int swap_flags);
asmlinkage long compat_sys_reboot(int magic1, int magic2, unsigned int cmd,
				void __user *arg);
asmlinkage long compat_sys_munmap(unsigned long addr, size_t len);
asmlinkage long compat_sys_munmap(unsigned long addr, size_t len);
asmlinkage long compat_sys_syslog(int type, char __user *buf, int len);
asmlinkage long compat_sys_swapoff(const char __user *specialfile);
asmlinkage long compat_sys_setdomainname(char __user *name, int len);
asmlinkage long compat_sys_newuname(struct new_utsname __user *name);
asmlinkage long compat_sys_mprotect(unsigned long start, size_t len,
				unsigned long prot);
asmlinkage long compat_sys_init_module(void __user *umod, unsigned long len,
				const char __user *uargs);
asmlinkage long compat_sys_delete_module(const char __user *name_user,
				unsigned int flags);
asmlinkage long compat_sys_quotactl(unsigned int cmd, const char __user *special,
				qid_t id, void __user *addr);
asmlinkage long compat_sys_bdflush(int func, long data);
asmlinkage long compat_sys_sysfs(int option,
				unsigned long arg1, unsigned long arg2);
asmlinkage long compat_sys_llseek(unsigned int fd, unsigned long offset_high,
			unsigned long offset_low, loff_t __user *result,
			unsigned int whence);
asmlinkage long compat_sys_msync(unsigned long start, size_t len, int flags);
asmlinkage long compat_sys_mlock(unsigned long start, size_t len);
asmlinkage long compat_sys_munlock(unsigned long start, size_t len);
asmlinkage long compat_sys_sched_setparam(pid_t pid,
					struct sched_param __user *param);
asmlinkage long compat_sys_sched_getparam(pid_t pid,
					struct sched_param __user *param);
asmlinkage long compat_sys_sched_setscheduler(pid_t pid, int policy,
					struct sched_param __user *param);
asmlinkage long compat_sys_mremap(unsigned long addr,
			   unsigned long old_len, unsigned long new_len,
			   unsigned long flags, unsigned long new_addr);
asmlinkage long compat_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
				int timeout);
asmlinkage long compat_sys_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5);
asmlinkage long compat_sys_getcwd(char __user *buf, unsigned long size);
asmlinkage long compat_sys_capget(cap_user_header_t header,
				cap_user_data_t dataptr);
asmlinkage long compat_sys_capset(cap_user_header_t header,
				const cap_user_data_t data);
asmlinkage long compat_sys_lchown(const char __user *filename,
				uid_t user, gid_t group);
asmlinkage long compat_sys_getgroups(int gidsetsize, gid_t __user *grouplist);
asmlinkage long compat_sys_setgroups(int gidsetsize, gid_t __user *grouplist);
asmlinkage long compat_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
asmlinkage long compat_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
asmlinkage long compat_sys_chown(const char __user *filename,
				uid_t user, gid_t group);
asmlinkage long compat_sys_pivot_root(const char __user *new_root,
				const char __user *put_old);
asmlinkage long compat_sys_mincore(unsigned long start, size_t len,
				unsigned char __user * vec);
asmlinkage long compat_sys_madvise(unsigned long start, size_t len, int behavior);
asmlinkage long compat_sys_setxattr(const char __user *path, const char __user *name,
			     const void __user *value, size_t size, int flags);
asmlinkage long compat_sys_lsetxattr(const char __user *path, const char __user *name,
			      const void __user *value, size_t size, int flags);
asmlinkage long compat_sys_fsetxattr(int fd, const char __user *name,
			      const void __user *value, size_t size, int flags);
asmlinkage long compat_sys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count);
asmlinkage long compat_sys_getxattr(const char __user *path, const char __user *name,
			     void __user *value, size_t size);
asmlinkage long compat_sys_lgetxattr(const char __user *path, const char __user *name,
			      void __user *value, size_t size);
asmlinkage long compat_sys_fgetxattr(int fd, const char __user *name,
			      void __user *value, size_t size);
asmlinkage long compat_sys_listxattr(const char __user *path, char __user *list,
			      size_t size);
asmlinkage long compat_sys_llistxattr(const char __user *path, char __user *list,
			       size_t size);
asmlinkage long compat_sys_flistxattr(int fd, char __user *list, size_t size);
asmlinkage long compat_sys_listxattr(const char __user *path, char __user *list,
			      size_t size);
asmlinkage long compat_sys_llistxattr(const char __user *path, char __user *list,
			       size_t size);
asmlinkage long compat_sys_flistxattr(int fd, char __user *list, size_t size);
asmlinkage long compat_sys_removexattr(const char __user *path,
				const char __user *name);
asmlinkage long compat_sys_lremovexattr(const char __user *path,
				 const char __user *name);
asmlinkage long compat_sys_fremovexattr(int fd, const char __user *name);
asmlinkage long compat_sys_set_tid_address(int __user *tidptr);
asmlinkage long compat_sys_epoll_ctl(int epfd, int op, int fd,
				struct epoll_event __user *event);
asmlinkage long compat_sys_epoll_wait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout);
asmlinkage long compat_sys_io_destroy(aio_context_t ctx);
asmlinkage long compat_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
			      struct io_event __user *result);
asmlinkage long compat_sys_mq_unlink(const char __user *name);
asmlinkage long compat_sys_add_key(const char __user *_type,
			    const char __user *_description,
			    const void __user *_payload,
			    size_t plen,
			    key_serial_t destringid);
asmlinkage long compat_sys_request_key(const char __user *_type,
				const char __user *_description,
				const char __user *_callout_info,
				key_serial_t destringid);
asmlinkage long compat_sys_remap_file_pages(unsigned long start, unsigned long size,
			unsigned long prot, unsigned long pgoff,
			unsigned long flags);
asmlinkage long compat_sys_inotify_add_watch(int fd, const char __user *path,
					u32 mask);
asmlinkage long compat_sys_mknodat(int dfd, const char __user * filename, umode_t mode,
			    unsigned dev);
asmlinkage long compat_sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);
asmlinkage long compat_sys_fchownat(int dfd, const char __user *filename, uid_t user,
			     gid_t group, int flag);
asmlinkage long compat_sys_unlinkat(int dfd, const char __user * pathname, int flag);
asmlinkage long compat_sys_renameat(int olddfd, const char __user * oldname,
			     int newdfd, const char __user * newname);
asmlinkage long compat_sys_symlinkat(const char __user * oldname,
			      int newdfd, const char __user * newname);
asmlinkage long compat_sys_linkat(int olddfd, const char __user *oldname,
			   int newdfd, const char __user *newname, int flags);
asmlinkage long compat_sys_readlinkat(int dfd, const char __user *path, char __user *buf,
			       int bufsiz);
asmlinkage long compat_sys_fchmodat(int dfd, const char __user * filename,
			     umode_t mode);
asmlinkage long compat_sys_faccessat(int dfd, const char __user *filename, int mode);
asmlinkage long compat_sys_unshare(unsigned long unshare_flags);
asmlinkage long compat_sys_splice(int fd_in, loff_t __user *off_in,
			   int fd_out, loff_t __user *off_out,
			   size_t len, unsigned int flags);
asmlinkage long compat_sys_tee(int fdin, int fdout, size_t len, unsigned int flags);
asmlinkage long compat_sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
asmlinkage long compat_sys_pipe2(int __user *fildes, int flags);
asmlinkage long compat_sys_perf_event_open(
		struct perf_event_attr __user *attr_uptr,
		pid_t pid, int cpu, int group_fd, unsigned long flags);

#ifdef CONFIG_CLONE_BACKWARDS
asmlinkage long compat_sys_clone(unsigned long, unsigned long, int __user *, unsigned long,
	       int __user *);
#else
#ifdef CONFIG_CLONE_BACKWARDS3
asmlinkage long compat_sys_clone(unsigned long, unsigned long, int, int __user *,
			  int __user *, unsigned long);
#else
asmlinkage long compat_sys_clone(unsigned long, unsigned long, int __user *,
	       int __user *, unsigned long);
#endif
#endif

asmlinkage long compat_sys_prlimit64(pid_t pid, unsigned int resource,
				const struct rlimit64 __user *new_rlim,
				struct rlimit64 __user *old_rlim);
asmlinkage long compat_sys_name_to_handle_at(int dfd, const char __user *name,
				      struct file_handle __user *handle,
				      int __user *mnt_id, int flag);
asmlinkage long compat_sys_kcmp(pid_t pid1, pid_t pid2, int type,
			 unsigned long idx1, unsigned long idx2);
asmlinkage long compat_sys_finit_module(int fd, const char __user *uargs, int flags);
asmlinkage long compat_sys_sched_setattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int flags);
asmlinkage long compat_sys_sched_getattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int size,
					unsigned int flags);
asmlinkage long compat_sys_renameat2(int olddfd, const char __user *oldname,
			      int newdfd, const char __user *newname,
			      unsigned int flags);
asmlinkage long compat_sys_seccomp(unsigned int op, unsigned int flags,
			    const char __user *uargs);
asmlinkage long compat_sys_getrandom(char __user *buf, size_t count,
			      unsigned int flags);
asmlinkage long compat_sys_memfd_create(const char __user *uname_ptr, unsigned int flags);
asmlinkage long compat_sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);
asmlinkage long compat_sys_socketpair(int, int, int, int __user *);
asmlinkage long compat_sys_bind(int, struct sockaddr __user *, int);
asmlinkage long compat_sys_connect(int, struct sockaddr __user *, int);
asmlinkage long compat_sys_accept4(int, struct sockaddr __user *, int __user *, int);
asmlinkage long compat_sys_getsockname(int, struct sockaddr __user *, int __user *);
asmlinkage long compat_sys_getpeername(int, struct sockaddr __user *, int __user *);
asmlinkage long compat_sys_sendto(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int);
asmlinkage long compat_sys_mlock2(unsigned long start, size_t len, int flags);

#endif  /*__COMPAT_WRAPPER */
