#ifndef _LINUX_ELFCORE_COMPAT_H
#define _LINUX_ELFCORE_COMPAT_H

#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/compat.h>
#include <linux/time.h>

/*
 * Make sure these layouts match the linux/elfcore.h native definitions.
 */

struct compat_elf_siginfo
{
	compat_int_t			si_signo;
	compat_int_t			si_code;
	compat_int_t			si_errno;
};

struct compat_elf_prstatus
{
	struct compat_elf_siginfo	pr_info;
	short				pr_cursig;
	compat_ulong_t			pr_sigpend;
	compat_ulong_t			pr_sighold;
	compat_pid_t			pr_pid;
	compat_pid_t			pr_ppid;
	compat_pid_t			pr_pgrp;
	compat_pid_t			pr_sid;
	struct compat_timeval		pr_utime;
	struct compat_timeval		pr_stime;
	struct compat_timeval		pr_cutime;
	struct compat_timeval		pr_cstime;
	compat_elf_gregset_t		pr_reg;
#ifdef CONFIG_BINFMT_ELF_FDPIC
	compat_ulong_t			pr_exec_fdpic_loadmap;
	compat_ulong_t			pr_interp_fdpic_loadmap;
#endif
	compat_int_t			pr_fpvalid;
};

struct compat_elf_prpsinfo
{
	char				pr_state;
	char				pr_sname;
	char				pr_zomb;
	char				pr_nice;
	compat_ulong_t			pr_flag;
	__compat_uid_t			pr_uid;
	__compat_gid_t			pr_gid;
	compat_pid_t			pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char				pr_fname[16];
	char				pr_psargs[ELF_PRARGSZ];
};

/*
 * Rename the basic ELF layout types to refer to the 32-bit class of files.
 */
#undef	ELF_CLASS
#define ELF_CLASS	ELFCLASS32

#undef	elfhdr
#undef	elf_phdr
#undef	elf_shdr
#undef	elf_note
#undef	elf_addr_t
#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_shdr	elf32_shdr
#define elf_note	elf32_note
#define elf_addr_t	Elf32_Addr

/*
 * Some data types as stored in coredump.
 */
#define user_long_t		compat_long_t
#define user_siginfo_t		compat_siginfo_t
#define copy_siginfo_to_user	copy_siginfo_to_user32

/*
 * The machine-dependent core note format types are defined in elfcore-compat.h,
 * which requires asm/elf.h to define compat_elf_gregset_t et al.
 */
#define elf_prstatus	compat_elf_prstatus
#define elf_prpsinfo	compat_elf_prpsinfo

/*
 * Compat version of cputime_to_compat_timeval, perhaps this
 * should be an inline in <linux/compat.h>.
 */
static void cputime_to_compat_timeval(const cputime_t cputime,
				      struct compat_timeval *value)
{
	struct timeval tv;
	cputime_to_timeval(cputime, &tv);
	value->tv_sec = tv.tv_sec;
	value->tv_usec = tv.tv_usec;
}

#undef cputime_to_timeval
#define cputime_to_timeval cputime_to_compat_timeval


/*
 * To use this file, asm/elf.h must define compat_elf_check_arch.
 * The other following macros can be defined if the compat versions
 * differ from the native ones, or omitted when they match.
 */

#undef	ELF_ARCH
#undef	elf_check_arch
#define	elf_check_arch	compat_elf_check_arch

#ifdef	COMPAT_ELF_PLATFORM
#undef	ELF_PLATFORM
#define	ELF_PLATFORM		COMPAT_ELF_PLATFORM
#endif

#ifdef	COMPAT_ELF_HWCAP
#undef	ELF_HWCAP
#define	ELF_HWCAP		COMPAT_ELF_HWCAP
#endif

#ifdef	COMPAT_ELF_HWCAP2
#undef	ELF_HWCAP2
#define	ELF_HWCAP2		COMPAT_ELF_HWCAP2
#endif

#ifdef	COMPAT_ARCH_DLINFO
#undef	ARCH_DLINFO
#define	ARCH_DLINFO		COMPAT_ARCH_DLINFO
#endif

#ifdef	COMPAT_ELF_ET_DYN_BASE
#undef	ELF_ET_DYN_BASE
#define	ELF_ET_DYN_BASE		COMPAT_ELF_ET_DYN_BASE
#endif

#ifdef COMPAT_ELF_EXEC_PAGESIZE
#undef	ELF_EXEC_PAGESIZE
#define	ELF_EXEC_PAGESIZE	COMPAT_ELF_EXEC_PAGESIZE
#endif

#ifdef	COMPAT_ELF_PLAT_INIT
#undef	ELF_PLAT_INIT
#define	ELF_PLAT_INIT		COMPAT_ELF_PLAT_INIT
#endif

#ifdef	COMPAT_SET_PERSONALITY
#undef	SET_PERSONALITY
#define	SET_PERSONALITY		COMPAT_SET_PERSONALITY
#endif

#ifdef	compat_start_thread
#undef	start_thread
#define	start_thread		compat_start_thread
#endif

#ifdef	compat_arch_setup_additional_pages
#undef	ARCH_HAS_SETUP_ADDITIONAL_PAGES
#define ARCH_HAS_SETUP_ADDITIONAL_PAGES 1
#undef	arch_setup_additional_pages
#define	arch_setup_additional_pages compat_arch_setup_additional_pages
#endif

/*
 * Rename a few of the symbols that binfmt_elf.c will define.
 * These are all local so the names don't really matter, but it
 * might make some debugging less confusing not to duplicate them.
 */
#define elf_format		compat_elf_format
#define init_elf_binfmt		init_compat_elf_binfmt
#define exit_elf_binfmt		exit_compat_elf_binfmt

#endif /* _LINUX_ELFCORE_COMPAT_H */
