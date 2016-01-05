/*
 * Support for ILP32 Linux/aarch64 ELF binaries.
 */

/* AARCH64 ILP32 EABI. */
#define compat_elf_check_arch(x)	(((x)->e_machine == EM_AARCH64)	\
					&& (x)->e_ident[EI_CLASS] == ELFCLASS32)

#define COMPAT_SET_PERSONALITY(ex)					\
do {									\
	set_thread_flag(TIF_32BIT_AARCH64);				\
	clear_thread_flag(TIF_32BIT);					\
} while (0)

#define COMPAT_ARCH_DLINFO						\
do {									\
	NEW_AUX_ENT(AT_SYSINFO_EHDR,					\
		    (elf_addr_t)(long)current->mm->context.vdso);	\
} while (0)

#include "../../../fs/compat_binfmt_elf.c"
