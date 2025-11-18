/* SPDX-License-Identifier: GPL-2.0-or-later */

#define pr_fmt(fmt) "SSE NMI: " fmt

#include <linux/atomic.h>
#include <linux/riscv_sbi_sse.h>
#include <linux/riscv_sse_nmi.h>

#include <asm/irq_regs.h>
#include <asm/sbi.h>
#include <asm/smp.h>

#define NMI_HANDLE(mask, func, ...) \
	do { if (type & (mask)) func(__VA_ARGS__); } while (0)

bool nmi_available;
static struct sse_event *local_nmi_evt;
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

static int local_nmi_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	enum local_nmi_type type = atomic_read((atomic_t *)arg);
	unsigned int cpu = smp_processor_id();

	NMI_HANDLE(LOCAL_NMI_CRASH, cpu_crash_stop, cpu, regs);
	NMI_HANDLE(LOCAL_NMI_STOP, cpu_stop);

	atomic_set(&local_nmi_arg, LOCAL_NMI_NONE);

	return 0;
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

	return 0;
}

late_initcall(sse_nmi_init);
