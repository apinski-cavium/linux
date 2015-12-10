/*
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Cavium Networks.
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

#ifndef __ASM_SIGNAL_COMMON_H
#define __ASM_SIGNAL_COMMON_H

#include <linux/uaccess.h>
#include <asm/ucontext.h>
#include <asm/fpsimd.h>

struct sigframe {
	struct ucontext uc;
	u64 fp;
	u64 lr;
};

int preserve_fpsimd_context(struct fpsimd_context __user *ctx);
int restore_fpsimd_context(struct fpsimd_context __user *ctx);
int setup_sigframe(struct sigframe __user *sf, struct pt_regs *regs, sigset_t *set);
int restore_sigframe(struct pt_regs *regs, struct sigframe __user *sf);
void setup_return(struct pt_regs *regs, struct k_sigaction *ka,
			void __user *frame, off_t sigframe_off, int usig);

#endif /* __ASM_SIGNAL_COMMON_H */
