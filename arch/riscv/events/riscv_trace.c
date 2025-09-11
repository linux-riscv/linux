// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_BASENAME ": " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/perf_event.h>
#include <linux/vmalloc.h>

#include "riscv_trace.h"

LIST_HEAD(riscv_trace_controllers);
static struct riscv_trace_pmu riscv_trace_pmu;

PMU_FORMAT_ATTR(start_addr, "config:0-63");
PMU_FORMAT_ATTR(stop_addr,  "config1:0-63");

static struct attribute *riscv_trace_filter_attrs[] = {
	&format_attr_start_addr.attr,
	&format_attr_stop_addr.attr,
	NULL,
};

static struct attribute_group riscv_trace_filter_attr_group = {
	.name = "format",
	.attrs = riscv_trace_filter_attrs,
};

static const struct attribute_group *riscv_trace_attr_groups[] = {
	&riscv_trace_filter_attr_group,
	NULL
};

static void riscv_trace_init_filter_attrs(struct perf_event *event)
{
	riscv_trace_pmu.filter_attr.start_addr = event->attr.config;
	riscv_trace_pmu.filter_attr.stop_addr  = event->attr.config1;

	if (event->attr.exclude_kernel)
		riscv_trace_pmu.filter_attr.priv_mode =
		    RISCV_TRACE_PRIV_MODE_EXCL_KERN;
	else if (event->attr.exclude_user)
		riscv_trace_pmu.filter_attr.priv_mode =
		    RISCV_TRACE_PRIV_MODE_EXCL_USER;
	else
		riscv_trace_pmu.filter_attr.priv_mode =
		    RISCV_TRACE_PRIV_MODE_EXCL_NONE;

	pr_info("start_addr=0x%llx stop_addr=0x%llx priv_mode=%d\n",
		riscv_trace_pmu.filter_attr.start_addr,
		riscv_trace_pmu.filter_attr.stop_addr,
		riscv_trace_pmu.filter_attr.priv_mode);
}

static int riscv_trace_event_init(struct perf_event *event)
{
	if (event->attr.type != riscv_trace_pmu.pmu.type)
		return -ENOENT;

	riscv_trace_init_filter_attrs(event);

	return 0;
}

static int riscv_trace_event_add(struct perf_event *event, int flags)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	// TODO: Configuring the trace component
	return 0;
}

static void riscv_trace_event_del(struct perf_event *event, int flags)
{
	// TODO: Reset the trace component
	pr_info("%s:%d\n", __func__, __LINE__);
}

static void riscv_trace_event_start(struct perf_event *event, int flags)
{
	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__,
		event->oncpu, event->cpu);
	// TODO: Begin aux buffer
	// struct xuantie_ntrace_aux_buf *buf;
	// buf = perf_aux_output_begin(&riscv_trace_pmu.handle, event);
	// TODO: Enable the trace component
}

static void riscv_trace_event_stop(struct perf_event *event, int flags)
{
	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__,
		event->oncpu, event->cpu);
	// TODO: Disable the trace component
	// TODO: End aux buffer
	// struct xuantie_ntrace_aux_buf *buf;
	// buf = perf_get_aux(&riscv_trace_pmu.handle);
	// Fill aux buffer
	// perf_aux_output_end(&riscv_trace_pmu.handle, size);
}

static void *riscv_trace_buffer_setup_aux(struct perf_event *event, void **pages,
					 int nr_pages, bool overwrite)
{
	struct riscv_trace_aux_buf *buf;
	struct page **pagelist;
	int i;

	if (overwrite) {
		pr_warn("Overwrite mode is not supported\n");
		return NULL;
	}

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	pagelist = kcalloc(nr_pages, sizeof(*pagelist), GFP_KERNEL);
	if (!pagelist)
		goto err;

	for (i = 0; i < nr_pages; i++)
		pagelist[i] = virt_to_page(pages[i]);

	buf->base = vmap(pagelist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base) {
		kfree(pagelist);
		goto err;
	}

	buf->nr_pages = nr_pages;
	buf->length = nr_pages * PAGE_SIZE;
	buf->pos = 0;

	pr_info("nr_pages=%d length=%d\n", buf->nr_pages, buf->length);

	kfree(pagelist);
	return buf;
err:
	kfree(buf);
	return NULL;
}

static void riscv_trace_buffer_free_aux(void *aux)
{
	struct riscv_trace_aux_buf *buf = aux;

	vunmap(buf->base);
	kfree(buf);
}

static int __init riscv_trace_init(void)
{
	struct riscv_trace_component *component;

	riscv_trace_encoder_init();
	riscv_trace_funnel_init();
	riscv_trace_sink_init();

	if (get_list_count(&riscv_trace_controllers) == 0)
		return -ENXIO;

	list_for_each_entry(component, &riscv_trace_controllers, list) {
		pr_info("type=%s in_num=%d out_num=%d\n",
			riscv_trace_type2str(component->type),
			component->in_num, component->out_num);
		for (int i = 0; i < component->in_num; i++) {
			pr_info("\t in[%d] type=%s base_addr=0x%llx\n", i,
				riscv_trace_type2str(component->in[i]->type),
				component->in[i]->base_addr);
		}
		for (int j = 0; j < component->out_num; j++) {
			pr_info("\t out[%d] type=%s base_addr=0x%llx\n", j,
				riscv_trace_type2str(component->out[j]->type),
				component->out[j]->base_addr);
		}
	}

	riscv_trace_pmu.pmu.module       = THIS_MODULE,
	riscv_trace_pmu.pmu.name         = "riscv_trace",
	riscv_trace_pmu.pmu.capabilities = PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE;
	riscv_trace_pmu.pmu.attr_groups  = riscv_trace_attr_groups;
	riscv_trace_pmu.pmu.task_ctx_nr  = perf_sw_context,
	riscv_trace_pmu.pmu.event_init   = riscv_trace_event_init;
	riscv_trace_pmu.pmu.add          = riscv_trace_event_add;
	riscv_trace_pmu.pmu.del          = riscv_trace_event_del;
	riscv_trace_pmu.pmu.start        = riscv_trace_event_start;
	riscv_trace_pmu.pmu.stop         = riscv_trace_event_stop;
	riscv_trace_pmu.pmu.setup_aux    = riscv_trace_buffer_setup_aux;
	riscv_trace_pmu.pmu.free_aux     = riscv_trace_buffer_free_aux;

	return perf_pmu_register(&riscv_trace_pmu.pmu, "riscv_trace", -1);
}

static void __exit riscv_trace_exit(void)
{
	perf_pmu_unregister(&riscv_trace_pmu.pmu);
}

module_init(riscv_trace_init);
module_exit(riscv_trace_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Pei <cp0613@linux.alibaba.com>");
MODULE_DESCRIPTION("Driver for RISC-V Trace Device");
