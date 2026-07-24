// SPDX-License-Identifier: GPL-2.0-only

#include <asm/vendor_extensions/sifive.h>
#include <asm/vendor_extensions/sifive_hwprobe.h>
#include <asm/vendor_extensions/vendor_hwprobe.h>

#include <linux/cpumask.h>
#include <linux/types.h>
#include <asm/vector.h>

#include <uapi/asm/hwprobe.h>
#include <uapi/asm/vendor/sifive.h>

void hwprobe_isa_vendor_ext_sifive_0(struct riscv_hwprobe *pair, const struct cpumask *cpus,
				     bool test_avail)
{
	bool report_v = test_avail ? riscv_v_vstate_ctrl_user_allowed() : true;

	VENDOR_EXTENSION_SUPPORTED(pair, cpus,
				   riscv_isa_vendor_ext_list_sifive.per_hart_isa_bitmap, {
		if (report_v) {
			VENDOR_EXT_KEY(XSFVQMACCDOD);
			VENDOR_EXT_KEY(XSFVQMACCQOQ);
			VENDOR_EXT_KEY(XSFVFNRCLIPXFQF);
			VENDOR_EXT_KEY(XSFVFWMACCQQQ);
		}
	});
}
