#ifndef __ASM_COMPAT_WRAPPER
#define __ASM_COMPAT_WRAPPER

/*
 *  Compat system call wrappers.
 *
 *    Copyright IBM Corp. 2014
 */

#define __SC_COMPAT_CAST(t, a)						\
({									\
	long __ReS = a;							\
									\
	BUILD_BUG_ON((sizeof(t) > 4) && !__TYPE_IS_L(t) &&		\
		     !__TYPE_IS_UL(t) && !__TYPE_IS_PTR(t));		\
	if (__TYPE_IS_L(t))						\
		__ReS = (s32)a;						\
	if (__TYPE_IS_UL(t))						\
		__ReS = (u32)a;						\
	if (__TYPE_IS_PTR(t))						\
		__ReS = a & 0x7fffffff;					\
	(t)__ReS;							\
})

#endif /* __ASM_COMPAT_WRAPPER */
