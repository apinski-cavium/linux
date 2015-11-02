#include <linux/linkage.h>
#include <linux/const.h>

#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/errno.h>
#include <asm/page.h>

ENTRY(compat_sys_statfs64_wrapper)
	mov	w3, #84
	cmp	w1, #88
	csel	w1, w3, w1, eq
	b	compat_sys_statfs64
ENDPROC(compat_sys_statfs64_wrapper)

ENTRY(compat_sys_fstatfs64_wrapper)
	mov	w3, #84
	cmp	w1, #88
	csel	w1, w3, w1, eq
	b	compat_sys_fstatfs64
ENDPROC(compat_sys_fstatfs64_wrapper)

/*
 * Note: off_4k (w5) is always in units of 4K. If we can't do the
 * requested offset because it is not page-aligned, we return -EINVAL.
 */
ENTRY(compat_sys_mmap2_wrapper)
#if PAGE_SHIFT > 12
	tst	w5, #~PAGE_MASK >> 12
	b.ne	1f
	lsr	w5, w5, #PAGE_SHIFT - 12
#endif
	b	sys_mmap_pgoff
1:	mov	x0, #-EINVAL
	ret
ENDPROC(compat_sys_mmap2_wrapper)

