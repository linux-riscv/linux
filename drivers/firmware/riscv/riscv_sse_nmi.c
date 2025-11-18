/* SPDX-License-Identifier: GPL-2.0-or-later */

#define pr_fmt(fmt) "SSE NMI: " fmt

#include <linux/atomic.h>
#include <linux/kgdb.h>
#include <linux/nmi.h>
#include <linux/riscv_sbi_sse.h>
#include <linux/riscv_sse_nmi.h>
#include <linux/sysctl.h>

#include <asm/irq_regs.h>
#include <asm/sbi.h>
#include <asm/smp.h>

#define NMI_HANDLE(mask, func, ...) \
	do { if (type & (mask)) func(__VA_ARGS__); } while (0)

bool nmi_available;
static int unknown_nmi_panic;
static struct sse_event *local_nmi_evt;
static struct sse_event *unknown_nmi_evt;
static struct ctl_table_header *unknown_nmi_sysctl_header;
static atomic_t local_nmi_arg = ATOMIC_INIT(LOCAL_NMI_NONE);

bool nmi_support(void)
{
	return READ_ONCE(nmi_available);
}

static inline struct sbiret sbi_sse_ecall(int fid, unsigned long arg0,
					  unsigned long arg1)
{
	return sbi_ecall(SBI_EXT_SSE, fid, arg0, arg1, 0, 0, 0, 0);
}

void send_nmi_single(unsigned int cpu, enum local_nmi_type type)
{
	unsigned int hart_id = cpuid_to_hartid_map(cpu);
	u32 evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED;
	struct sbiret ret;

	atomic_or(type, &local_nmi_arg);
	ret = sbi_sse_ecall(SBI_SSE_EVENT_INJECT, evt, hart_id);
	if (ret.error)
		pr_err("Failed to signal event %x to hartid %d, error %ld\n",
		       evt, hart_id, ret.error);
}

void send_nmi_mask(cpumask_t *mask, enum local_nmi_type type)
{
	unsigned int cpu;

	for_each_cpu(cpu, mask)
		send_nmi_single(cpu, type);
}

static int __init setup_unknown_nmi_panic(char *str)
{
	unknown_nmi_panic = 1;
	return 1;
}
__setup("unknown_nmi_panic", setup_unknown_nmi_panic);

static const struct ctl_table unknown_nmi_table[] = {
	{
		.procname       = "unknown_nmi_panic",
		.data           = &unknown_nmi_panic,
		.maxlen         = sizeof(bool),
		.mode           = 0644,
		.proc_handler   = proc_dobool,
	},
};

static int unknown_nmi_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	pr_emerg("NMI received for unknown on CPU %d.\n", smp_processor_id());

	if (unknown_nmi_panic)
		nmi_panic(regs, "NMI: Not continuing");

	pr_emerg("Dazed and confused, but trying to continue\n");

	return 0;
}

static int local_nmi_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	enum local_nmi_type type = atomic_read((atomic_t *)arg);
	unsigned int cpu = smp_processor_id();

	NMI_HANDLE(LOCAL_NMI_CRASH, cpu_crash_stop, cpu, regs);
	NMI_HANDLE(LOCAL_NMI_STOP, cpu_stop);
	NMI_HANDLE(LOCAL_NMI_BACKTRACE, nmi_cpu_backtrace, regs);
	NMI_HANDLE(LOCAL_NMI_KGDB, kgdb_nmicallback, cpu, regs);

	atomic_set(&local_nmi_arg, LOCAL_NMI_NONE);

	return 0;
}

static int unknown_nmi_init(void)
{
	int ret;

	unknown_nmi_evt = sse_event_register(SBI_SSE_EVENT_LOCAL_UNKNOWN_NMI, 0,
					     unknown_nmi_handler, NULL);
	if (IS_ERR(unknown_nmi_evt))
		return PTR_ERR(unknown_nmi_evt);

	ret = sse_event_enable(unknown_nmi_evt);
	if (ret)
		goto err_unregister;

	unknown_nmi_sysctl_header = register_sysctl("kernel", unknown_nmi_table);
	if (!unknown_nmi_sysctl_header) {
		ret = -ENOMEM;
		goto err_disable;
	}

	pr_info("Using SSE for unknown NMI event delivery\n");
	return 0;

err_disable:
	sse_event_disable(unknown_nmi_evt);
err_unregister:
	sse_event_unregister(unknown_nmi_evt);
	return ret;
}

static int __init local_nmi_init(void)
{
	int ret;

	local_nmi_evt = sse_event_register(SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED, 0,
					   local_nmi_handler, &local_nmi_arg);
	if (IS_ERR(local_nmi_evt))
		return PTR_ERR(local_nmi_evt);

	ret = sse_event_enable(local_nmi_evt);
	if (ret) {
		sse_event_unregister(local_nmi_evt);
		return ret;
	}

	pr_info("Using SSE for Local NMI event delivery\n");

	return 0;
}

static int __init sse_nmi_init(void)
{
	int ret;

	ret = local_nmi_init();
	if (ret) {
		pr_err("Local_nmi_init failed with error %d\n", ret);
		return ret;
	}

	WRITE_ONCE(nmi_available, true);

	ret = unknown_nmi_init();
	if (ret) {
		pr_err("Unknown_nmi_init failed with error %d\n", ret);
		return ret;
	}

	return 0;
}

late_initcall(sse_nmi_init);
