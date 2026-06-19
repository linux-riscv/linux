/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/cpufeature-macros.h>

static inline bool cpu_supports_zacas(void)
{
	return IS_ENABLED(CONFIG_RISCV_ISA_ZACAS) && IS_ENABLED(CONFIG_TOOLCHAIN_HAS_ZACAS) &&
		riscv_has_extension_unlikely(RISCV_ISA_EXT_ZACAS);
}
