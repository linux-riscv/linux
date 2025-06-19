// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Rivos Inc. */

#include <asm/sbi.h>

long __sbi_base_ecall(int fid)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_BASE, fid);
	if (!ret.error)
		return ret.value;
	else
		return sbi_err_map_linux_errno(ret.error);
}
EXPORT_SYMBOL(__sbi_base_ecall);
