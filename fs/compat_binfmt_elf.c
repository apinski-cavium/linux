/*
 * 32-bit compatibility support for ELF format executables and core dumps.
 *
 * Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Red Hat Author: Roland McGrath.
 *
 * This file is used in a 64-bit kernel that wants to support 32-bit ELF.
 * asm/elf.h is responsible for defining the compat_* and COMPAT_* macros
 * used below, with definitions appropriate for 32-bit ABI compatibility.
 *
 * We use macros to rename the ABI types and machine-dependent
 * functions used in binfmt_elf.c to compat versions.
 */

#include <linux/elfcore-compat.h>

/*
 * We share all the actual code with the native (64-bit) version.
 */
#include "binfmt_elf.c"
