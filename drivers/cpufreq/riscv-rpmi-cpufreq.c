// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V MPXY Based CPUFreq Driver
 *
 * Copyright (C) 2026 Shanghai StarFive Technology Co., Ltd.
 */

#define pr_fmt(fmt) "riscv-rpmi-performance: " fmt

#include <linux/bitfield.h>
#include <linux/bsearch.h>
#include <linux/cpufreq.h>
#include <linux/io.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/platform_device.h>

#define RPMI_PERF_DOMAIN_NAME_LEN		16

struct rpmi_perf_opp {
	u32 index;
	u32 clock_freq;
	u32 power_cost;
	u32 trans_latency_us;
};

struct rpmi_fc_db_info {
	int width;
	u64 set;
	void __iomem *addr;
};

struct rpmi_fc_info {
	void __iomem *set_addr;
	void __iomem *get_addr;
	struct rpmi_fc_db_info *set_db;
};

struct rpmi_ctx {
	struct mbox_chan *chan;
	struct mbox_client client;
	u32 max_msg_size;
};

struct rpmi_fast_channel {
	u64 addr;
	u64 size;
};

struct rpmi_perf_domain {
	u32 id;
	bool set_limit;
	bool set_level;
	bool has_fastchannels;
	u32 opp_count;
	u32 rate_limit_us;
	char name[RPMI_PERF_DOMAIN_NAME_LEN];
	struct rpmi_perf_opp *opp;
	struct rpmi_fc_info *fc_info;
	struct rpmi_ctx *mpxy_ctx;
	struct device *dev;
	struct rpmi_perf *perf;
};

struct rpmi_perf {
	u32 num_domains;
	struct rpmi_fast_channel fast_channel;
	struct device *dev;
	struct rpmi_perf_domain *domain;
};

struct rpmi_perf_cpufreq_data {
	int cpufreq_domain_id;
	int nr_opp;
	struct device *cpu_dev;
	struct rpmi_perf *mpxy_perf;
};

enum {
	RPMI_PERF_FC_LEVEL,
	RPMI_PERF_FC_LIMIT,
	RPMI_PERF_FC_MAX,
};

/* Service: ENABLE_NOTIFICATION */
struct rpmi_perf_enable_notification_tx {
	u32 event_id;
};

struct rpmi_perf_enable_notification_rx {
	s32 status;
};

/* Service: GET_NUM_DOMAINS */
struct rpmi_perf_get_num_domain_rx {
	s32 status;
	u32 num_domains;
};

/* Service: GET_ATTRS */
struct rpmi_perf_get_attrs_tx {
	u32 domain_id;
};

struct rpmi_perf_get_attrs_rx {
	s32 status;
	u32 flags;
#define PERF_LIMIT_SETTING(f)		(FIELD_GET(BIT(2), (f)))
#define PERF_LEVEL_SETTING(f)		(FIELD_GET(BIT(1), (f)))
#define FAST_CHANNEL_SUPPORT(f)		(FIELD_GET(BIT(0), (f)))
	u32 num_levels;
	u32 trans_latency_us;
	char name[RPMI_PERF_DOMAIN_NAME_LEN];
};

/* Service: GET_SUPPORTED_LEVELS */
struct rpmi_perf_get_supported_level_tx {
	u32 domain_id;
	u32 level_index;
};

struct rpmi_perf_get_supported_level_rx {
	s32 status;
	u32 flags;
	u32 remaining;
	u32 returned;
	struct rpmi_perf_opp opp[];
};

/* Service: GET_LEVELS */
struct rpmi_perf_get_level_tx {
	u32 domain_id;
};

struct rpmi_perf_get_level_rx {
	s32 status;
	u32 level_index;
};

/* Service: SET_LEVELS */
struct rpmi_perf_set_level_tx {
	u32 domain_id;
	u32 level_index;
};

struct rpmi_perf_set_level_rx {
	s32 status;
};

/* Service: GET_FAST_CHANNEL_REGION */
struct rpmi_perf_get_fast_channel_region_rx {
	s32 status;
	u32 addr_low;
	u32 addr_high;
	u32 size_low;
	u32 size_high;
};

/* Service: GET_FAST_CHANNEL_ATTRIBUTES */
struct rpmi_perf_get_fast_channel_attributes_tx {
	u32 domain_id;
	u32 service_id;
};

struct rpmi_perf_get_fast_channel_attributes_rx {
	s32 status;
	u32 flags;
#define DOORBELL_REG_WIDTH(f)	(FIELD_GET(GENMASK(2, 1), (f)))
#define SUPPORTS_DOORBELL(f)	(FIELD_GET(BIT(0), (f)))
	u32 offset_low;
	u32 offset_high;
	u32 size;
	u32 db_addr_low;
	u32 db_addr_high;
	u32 db_id;
};

static void rpmi_perf_fastchannel_db_ring(struct rpmi_fc_db_info *db)
{
	if (!db || !db->addr)
		return;

	switch (db->width) {
	case 8:
		iowrite8((u8)db->set, db->addr);
		break;
	case 16:
		iowrite16((u16)db->set, db->addr);
		break;
	case 32:
		iowrite32((u32)db->set, db->addr);
		break;
	}
}

static int rpmi_perf_get_num_domains(struct rpmi_ctx *mpxy_ctx, u32 *domain)
{
	struct rpmi_perf_get_num_domain_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_NUM_DOMAINS,
					  NULL, 0, &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	*domain = rx.num_domains;

	return 0;
}

static int rpmi_perf_get_attrs(struct rpmi_perf *mpxy_perf, struct rpmi_perf_domain *perf_domain)
{
	struct rpmi_perf_get_attrs_tx tx;
	struct rpmi_perf_get_attrs_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	tx.domain_id = perf_domain->id;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_ATTRIBUTES,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(perf_domain->mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	perf_domain->set_limit = PERF_LIMIT_SETTING(rx.flags);
	perf_domain->set_level = PERF_LEVEL_SETTING(rx.flags);
	perf_domain->has_fastchannels = mpxy_perf->fast_channel.size &&
					(perf_domain->set_limit || perf_domain->set_level) ?
					FAST_CHANNEL_SUPPORT(rx.flags) : false;
	perf_domain->opp_count = rx.num_levels;
	perf_domain->rate_limit_us = rx.trans_latency_us;
	strscpy(perf_domain->name, rx.name, RPMI_PERF_DOMAIN_NAME_LEN);

	if (!perf_domain->opp_count)
		return -EINVAL;

	perf_domain->opp = devm_kcalloc(mpxy_perf->dev, perf_domain->opp_count,
					sizeof(struct rpmi_perf_opp), GFP_KERNEL);
	if (!perf_domain->opp)
		return -ENOMEM;

	return 0;
}

static int rpmi_perf_get_supported_levels(struct rpmi_perf_domain *perf_domain)
{
	struct rpmi_perf_get_supported_level_tx tx;
	struct rpmi_perf_get_supported_level_rx *rx;
	struct rpmi_mbox_message msg;
	struct rpmi_perf_opp *opp;
	u32 index = 0;
	int ret = 0;

	rx = devm_kcalloc(perf_domain->dev, perf_domain->mpxy_ctx->max_msg_size,
			  sizeof(u32), GFP_KERNEL);
	if (!rx)
		return -ENOMEM;

	do {
		tx.domain_id = perf_domain->id;
		tx.level_index = index;

		rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_SUPPORTED_LEVELS,
						  &tx, sizeof(tx), rx,
						  perf_domain->mpxy_ctx->max_msg_size);
		ret = rpmi_mbox_send_message(perf_domain->mpxy_ctx->chan, &msg);
		if (ret)
			goto exit;

		if (rx->status) {
			ret = rpmi_to_linux_error(rx->status);
			goto exit;
		}

		if ((index + rx->returned + rx->remaining) != perf_domain->opp_count) {
			ret = -EINVAL;
			goto exit;
		}

		for (int i = 0; i < rx->returned; i++) {
			opp = &perf_domain->opp[index + i];
			opp->index = rx->opp[i].index;
			opp->clock_freq = rx->opp[i].clock_freq;
			opp->power_cost = rx->opp[i].power_cost;
			opp->trans_latency_us = rx->opp[i].trans_latency_us;
		}

		index += rx->returned;

	} while (rx->remaining);

exit:
	devm_kfree(perf_domain->dev, rx);

	return ret;
}

static int rpmi_perf_get_levels(struct rpmi_perf_domain *perf_domain, u32 *level_index)
{
	struct rpmi_perf_get_level_tx tx;
	struct rpmi_perf_get_level_rx rx;
	struct rpmi_mbox_message msg;
	int ret = 0;

	tx.domain_id = perf_domain->id;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_LEVEL,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(perf_domain->mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	*level_index = rx.level_index;

	return 0;
}

static int rpmi_perf_set_levels(struct rpmi_perf_domain *perf_domain, u32 level_index)
{
	struct rpmi_perf_set_level_tx tx;
	struct rpmi_perf_set_level_rx rx;
	struct rpmi_mbox_message msg;
	int ret = 0;

	tx.domain_id = perf_domain->id;
	tx.level_index = level_index;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_SET_LEVEL,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(perf_domain->mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return 0;
}

static int rpmi_perf_get_fast_channel_regions(struct rpmi_ctx *mpxy_ctx, struct rpmi_perf *perf)
{
	struct rpmi_perf_get_fast_channel_region_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_FAST_CHANNEL_REGION,
					  NULL, 0, &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	perf->fast_channel.addr = rx.addr_low | (((u64)rx.addr_high) << 32);
	perf->fast_channel.size = rx.size_low | (((u64)rx.size_high) << 32);

	return 0;
}

static int rpmi_perf_extract_attributes(struct rpmi_perf_get_fast_channel_attributes_rx *rx,
					struct rpmi_perf_domain *domain,
					struct rpmi_fc_info *fc, u32 service_id)
{
	u64 phys_offset, phys_addr, db_phys_addr;
	struct rpmi_fc_db_info *db = NULL;
	void __iomem *addr, *db_addr;
	u8 db_addr_width;
	u32 flags;

	flags = le32_to_cpu(rx->flags);
	phys_offset = le32_to_cpu(rx->offset_low);
	phys_offset |= (u64)le32_to_cpu(rx->offset_high) << 32;
	phys_addr = domain->perf->fast_channel.addr + phys_offset;

	addr = devm_ioremap(domain->dev, phys_addr, 8);
	if (!addr) {
		dev_err(domain->dev,
			"failed to get fastchannel virtual addr in domain: %d\n",
			domain->id);
		return -EADDRNOTAVAIL;
	}

	switch (service_id) {
	case RPMI_PERF_SRV_GET_LEVEL:
	case RPMI_PERF_SRV_GET_LIMIT:
		fc->get_addr = addr;
		break;
	case RPMI_PERF_SRV_SET_LEVEL:
	case RPMI_PERF_SRV_SET_LIMIT:
		if (SUPPORTS_DOORBELL(flags)) {
			db = devm_kzalloc(domain->dev,
					  sizeof(struct rpmi_fc_db_info),
					  GFP_KERNEL);
			if (!db)
				break;

			db_addr_width = 1 << (DOORBELL_REG_WIDTH(flags) + 3);
			db_phys_addr = le32_to_cpu(rx->db_addr_low);
			db_phys_addr |= (u64)le32_to_cpu(rx->db_addr_high) << 32;

			db_addr = devm_ioremap(domain->dev, db_phys_addr, 8);
			if (!db_addr)
				break;

			db->addr = db_addr;
			db->width = db_addr_width;
			db->set = le32_to_cpu(rx->db_id);
			fc->set_db = db;
		}
		fc->set_addr = addr;

		break;
	}

	return 0;
}

static int rpmi_perf_get_fast_channel_attributes(struct rpmi_perf_domain *perf_domain,
						 struct rpmi_fc_info *fc,
						 u32 service_id)
{
	struct rpmi_perf_get_fast_channel_attributes_tx tx;
	struct rpmi_perf_get_fast_channel_attributes_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	tx.domain_id = perf_domain->id;
	tx.service_id = service_id;

	rpmi_mbox_init_send_with_response(&msg, RPMI_PERF_SRV_GET_FAST_CHANNEL_ATTRS,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(perf_domain->mpxy_ctx->chan, &msg);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	ret = rpmi_perf_extract_attributes(&rx, perf_domain, fc, service_id);

	return ret;
}

static int rpmi_perf_enumerate(struct rpmi_perf *mpxy_perf, struct rpmi_perf_domain *domain)
{
	struct rpmi_fc_info *fc;
	int ret, id;

	id = domain->id;

	ret = rpmi_perf_get_attrs(mpxy_perf, domain);
	if (ret) {
		dev_err(domain->dev,
			"Failed to get attributes of perf domain: #%u\n", id);
		return ret;
	}

	ret = rpmi_perf_get_supported_levels(domain);
	if (ret) {
		dev_err(domain->dev,
			"Failed to get supported level of perf domain: #%u\n", id);
		return ret;
	}

	if (domain->has_fastchannels) {
		fc = devm_kcalloc(domain->dev, RPMI_PERF_FC_MAX, sizeof(*fc), GFP_KERNEL);
		if (!fc)
			return -ENOMEM;

		if (domain->set_level) {
			rpmi_perf_get_fast_channel_attributes(domain,
							      &fc[RPMI_PERF_FC_LEVEL],
							      RPMI_PERF_SRV_SET_LEVEL);
		}

		rpmi_perf_get_fast_channel_attributes(domain,
						      &fc[RPMI_PERF_FC_LEVEL],
						      RPMI_PERF_SRV_GET_LEVEL);

		if (domain->set_limit) {
			rpmi_perf_get_fast_channel_attributes(domain,
							      &fc[RPMI_PERF_FC_LIMIT],
							      RPMI_PERF_SRV_SET_LIMIT);
		}

		rpmi_perf_get_fast_channel_attributes(domain,
						      &fc[RPMI_PERF_FC_LIMIT],
						      RPMI_PERF_SRV_GET_LIMIT);

		domain->fc_info = fc;
	}

	return 0;
}

static int rpmi_perf_dvfs_device_opps_add(const struct rpmi_perf *mpxy_perf,
					  struct device *dev, int domain)
{
	struct rpmi_perf_opp *opp;
	struct rpmi_perf_domain *dom;
	unsigned long freq;
	int idx, ret;

	if (domain < 0)
		return domain;
	else if (domain > mpxy_perf->num_domains)
		return -EINVAL;

	dom = mpxy_perf->domain + domain;

	for (opp = dom->opp, idx = 0; idx < dom->opp_count; idx++, opp++) {
		/* Frequency from RPMI is in kHz*/
		freq = opp->clock_freq * 1000;

		ret = dev_pm_opp_add(dev, freq, 0);
		if (ret) {
			dev_warn(dev, "failed to add opp %luHz\n", freq);

			while (idx-- > 0) {
				/* Frequency from RPMI is in kHz*/
				freq = (--opp)->clock_freq * 1000;
				dev_pm_opp_remove(dev, freq);
			}
			return ret;
		}
	}
	return 0;
}

static int rpmi_perf_search_index(const void *id, const void *opp)
{
	return *((u32 *)id) - ((struct rpmi_perf_opp *)opp)->index;
}

static int rpmi_perf_search_freq(const void *id, const void *opp)
{
	return *((u32 *)id) - ((struct rpmi_perf_opp *)opp)->clock_freq;
}

static int rpmi_perf_level_to_frequency(struct rpmi_perf_domain *domain, u32 index, u32 *cpufreq)
{
	struct rpmi_perf_opp *found;

	found = bsearch(&index, domain->opp, domain->opp_count,
			sizeof(domain->opp[0]), rpmi_perf_search_index);
	if (found) {
		*cpufreq = found->clock_freq;
		return 0;
	}

	return -EINVAL;
}

static int rpmi_perf_frequency_to_level(struct rpmi_perf_domain *domain, u32 clock_freq, u32 *index)
{
	struct rpmi_perf_opp *found;

	found = bsearch(&clock_freq, domain->opp, domain->opp_count,
			sizeof(domain->opp[0]), rpmi_perf_search_freq);
	if (found) {
		*index = found->index;
		return 0;
	}

	return -EINVAL;
}

static int rpmi_perf_set_target_index(struct cpufreq_policy *policy, unsigned int index)
{
	struct rpmi_perf_cpufreq_data *data = policy->driver_data;
	struct rpmi_perf_domain *domain;
	int ret;

	domain = &data->mpxy_perf->domain[data->cpufreq_domain_id];

	if (!domain->set_level) {
		dev_err(data->mpxy_perf->dev,
			"perf domain #%u - set perf level is not supported\n",
			data->cpufreq_domain_id);
		return -EOPNOTSUPP;
	}

	if (!domain->fc_info || !domain->fc_info[RPMI_PERF_FC_LEVEL].set_addr) {
		ret = rpmi_perf_set_levels(domain, index);
	} else {
		iowrite32(index, domain->fc_info[RPMI_PERF_FC_LEVEL].set_addr);
		rpmi_perf_fastchannel_db_ring(domain->fc_info[RPMI_PERF_FC_LEVEL].set_db);
		ret = 0;
	}

	return ret;
}

static unsigned int rpmi_perf_fast_switch(struct cpufreq_policy *policy,
					  unsigned int target_freq)
{
	struct rpmi_perf_cpufreq_data *data = policy->driver_data;
	struct rpmi_perf_domain *domain = &data->mpxy_perf->domain[data->cpufreq_domain_id];
	u32 level_index = 0;

	if (!rpmi_perf_frequency_to_level(domain, target_freq, &level_index))
		return 0;

	if (!rpmi_perf_set_target_index(policy, level_index))
		return target_freq;

	return 0;
}

static unsigned int rpmi_perf_get_rate(unsigned int cpu)
{
	struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);
	struct rpmi_perf_cpufreq_data *data = policy->driver_data;
	struct rpmi_perf_domain *domain;
	u32 cpufreq, level_index;
	unsigned long rate;
	int ret;

	domain = &data->mpxy_perf->domain[data->cpufreq_domain_id];

	if (!domain->fc_info || !domain->fc_info[RPMI_PERF_FC_LEVEL].get_addr) {
		ret = rpmi_perf_get_levels(&data->mpxy_perf->domain[data->cpufreq_domain_id],
					   &level_index);
		if (ret)
			return 0;
	} else {
		level_index = ioread32(domain->fc_info[RPMI_PERF_FC_LEVEL].get_addr);
	}

	ret = rpmi_perf_level_to_frequency(domain, level_index, &cpufreq);
	if (ret)
		return 0;

	rate = (unsigned long)cpufreq;

	return rate;
}

static int rpmi_perf_init(struct cpufreq_policy *policy)
{
	struct cpufreq_frequency_table *freq_table;
	struct rpmi_perf_cpufreq_data *data;
	struct rpmi_perf_domain *domain;
	struct of_phandle_args args;
	struct rpmi_perf *mpxy_perf;
	int ret, nr_opp, domain_id;
	struct device *cpu_dev;

	mpxy_perf = cpufreq_get_driver_data();

	cpu_dev = get_cpu_device(policy->cpu);
	if (!cpu_dev) {
		pr_err("failed to get cpu%d device\n", policy->cpu);
		return -ENODEV;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = of_perf_domain_get_sharing_cpumask(policy->cpu,
						 "performance-domains",
						 "#performance-domain-cells",
						 policy->cpus, &args);
	if (ret) {
		dev_err(cpu_dev, "%s: failed to performance domain info: %d\n",
			__func__, ret);
		goto out_free_priv;
	}

	domain_id = args.args[0];
	of_node_put(args.np);

	ret = rpmi_perf_dvfs_device_opps_add(mpxy_perf, cpu_dev, domain_id);
	if (ret) {
		dev_warn(cpu_dev, "failed to add opps to the device\n");
		goto out_free_priv;
	}

	nr_opp = dev_pm_opp_get_opp_count(cpu_dev);
	if (nr_opp <= 0) {
		dev_dbg(cpu_dev, "OPP table is not ready, deferring probe\n");
		ret = -EPROBE_DEFER;
		goto out_free_priv;
	}

	ret = dev_pm_opp_init_cpufreq_table(cpu_dev, &freq_table);
	if (ret) {
		dev_err(cpu_dev, "failed to init cpufreq table: %d\n", ret);
		goto out_free_opp;
	}

	data->cpu_dev = cpu_dev;
	data->nr_opp = nr_opp;
	data->cpufreq_domain_id = domain_id;
	data->mpxy_perf = mpxy_perf;

	/* Allow DVFS request for any domain from any CPU */
	policy->dvfs_possible_from_any_cpu = true;
	policy->driver_data = data;
	policy->freq_table = freq_table;

	domain = &mpxy_perf->domain[domain_id];
	policy->cpuinfo.transition_latency = domain->rate_limit_us * 1000;
	policy->fast_switch_possible = true;

	return 0;

out_free_opp:
	dev_pm_opp_remove_all_dynamic(cpu_dev);

out_free_priv:
	kfree(data);

	return ret;
}

static void rpmi_perf_exit(struct cpufreq_policy *policy)
{
	struct rpmi_perf_cpufreq_data *data = policy->driver_data;

	dev_pm_opp_free_cpufreq_table(data->cpu_dev, &policy->freq_table);
	dev_pm_opp_remove_all_dynamic(data->cpu_dev);
	kfree(data);
}

static int __maybe_unused
rpmi_perf_get_cpu_power(struct device *cpu_dev, unsigned long *uW,
			unsigned long *kHz)
{
	struct rpmi_perf_cpufreq_data *data;
	struct rpmi_perf_domain *domain;
	struct cpufreq_policy *policy;
	struct rpmi_perf_opp *opp;
	unsigned long Hz;
	int idx;

	policy = cpufreq_cpu_get_raw(cpu_dev->id);
	if (!policy)
		return 0;

	data = policy->driver_data;
	domain = &data->mpxy_perf->domain[data->cpufreq_domain_id];
	Hz = *kHz * 1000;

	for (opp = domain->opp, idx = 0; idx < domain->opp_count; idx++, opp++) {
		if (opp->clock_freq < *kHz)
			continue;

		*uW = opp->power_cost;
		*kHz = opp->clock_freq;
		break;
	}

	return 0;
}

static void rpmi_perf_register_em(struct cpufreq_policy *policy)
{
	struct em_data_callback em_cb = EM_DATA_CB(rpmi_perf_get_cpu_power);
	struct rpmi_perf_cpufreq_data *data = policy->driver_data;

	em_dev_register_perf_domain(get_cpu_device(policy->cpu), data->nr_opp,
				    &em_cb, policy->cpus, true);
}

static struct cpufreq_driver  rpmi_perf_cpufreq_driver = {
	.name = "sbi-mpxy-cpufreq",
	.flags = CPUFREQ_HAVE_GOVERNOR_PER_POLICY |
		 CPUFREQ_NEED_INITIAL_FREQ_CHECK |
		 CPUFREQ_IS_COOLING_DEV,
	.verify = cpufreq_generic_frequency_table_verify,
	.target_index = rpmi_perf_set_target_index,
	.fast_switch = rpmi_perf_fast_switch,
	.get = rpmi_perf_get_rate,
	.init = rpmi_perf_init,
	.exit = rpmi_perf_exit,
	.register_em = rpmi_perf_register_em,
};

static int rpmi_cpufreq_attr_setup(struct device *dev, struct rpmi_ctx *mpxy_ctx)
{
	struct rpmi_mbox_message msg;
	int ret;

	/* Validate RPMI specification version */
	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_SPEC_VERSION);
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret) {
		dev_dbg(dev, "Failed to get spec version\n");
		return ret;
	}

	if (msg.attr.value < RPMI_MKVER(1, 0)) {
		dev_dbg(dev,
			"msg protocol version mismatch, expected 0x%x, found 0x%x\n",
			RPMI_MKVER(1, 0), msg.attr.value);
		return -EINVAL;
	}

	/* Validate performance service group ID */
	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_SERVICEGROUP_ID);
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret) {
		dev_dbg(dev, "Failed to get service group ID\n");
		return ret;
	}

	if (msg.attr.value != RPMI_SRVGRP_PERFORMANCE) {
		dev_dbg(dev,
			"service group match failed, expected 0x%x, found 0x%x\n",
			RPMI_SRVGRP_PERFORMANCE, msg.attr.value);
		return -EINVAL;
	}

	/* Validate performance service group version */
	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_SERVICEGROUP_VERSION);
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret) {
		dev_dbg(dev, "Failed to get service group version\n");
		return ret;
	}

	if (msg.attr.value < RPMI_MKVER(1, 0)) {
		dev_dbg(dev,
			"service group version failed, expected 0x%x, found 0x%x\n",
			RPMI_MKVER(1, 0), msg.attr.value);
		return -EINVAL;
	}

	/* Get max message size */
	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE);
	ret = rpmi_mbox_send_message(mpxy_ctx->chan, &msg);
	if (ret) {
		dev_dbg(dev, "Failed to get max message data size\n");
		return ret;
	}

	mpxy_ctx->max_msg_size = msg.attr.value;

	return 0;
}

static int rpmi_cpufreq_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rpmi_perf *mpxy_perf;
	struct rpmi_ctx *mpxy_ctx;
	int num_domains = 0;
	int ret, i;

	mpxy_ctx = devm_kzalloc(&pdev->dev, sizeof(*mpxy_ctx), GFP_KERNEL);
	if (!mpxy_ctx)
		return -ENOMEM;

	/* Setup mailbox client */
	mpxy_ctx->client.dev		= dev;
	mpxy_ctx->client.rx_callback	= NULL;
	mpxy_ctx->client.tx_block	= false;
	mpxy_ctx->client.knows_txdone	= true;
	mpxy_ctx->client.tx_tout	= 0;

	/* Request mailbox channel */
	mpxy_ctx->chan = mbox_request_channel(&mpxy_ctx->client, 0);
	if (IS_ERR(mpxy_ctx->chan))
		return PTR_ERR(mpxy_ctx->chan);

	ret = rpmi_cpufreq_attr_setup(dev, mpxy_ctx);
	if (ret) {
		dev_err(dev, "failed to verify RPMI attribute - err:%d\n", ret);
		goto fail_free_channel;
	}

	/* Get number of performance domain */
	ret = rpmi_perf_get_num_domains(mpxy_ctx, &num_domains);
	if (ret) {
		dev_err(dev, "invalid number of perf domains - err:%d\n", ret);
		goto fail_free_channel;
	}

	if (!num_domains) {
		dev_err(dev, "No PM domains found!\n");
		ret = -EINVAL;
		goto fail_free_channel;
	}

	mpxy_perf = devm_kzalloc(dev, sizeof(*mpxy_perf), GFP_KERNEL);
	if (!mpxy_perf) {
		ret = -ENOMEM;
		goto fail_free_channel;
	}

	mpxy_perf->domain = devm_kcalloc(dev, num_domains,
					 sizeof(struct rpmi_perf_domain),
					 GFP_KERNEL);
	if (!mpxy_perf->domain) {
		ret = -ENOMEM;
		goto fail_free_channel;
	}

	mpxy_perf->num_domains = num_domains;
	mpxy_perf->dev = dev;

	/* Get fast channel region for performance domain */
	ret = rpmi_perf_get_fast_channel_regions(mpxy_ctx, mpxy_perf);
	if (ret)
		dev_err(dev, "invalid fast channel region\n");

	for (i = 0; i < num_domains; i++) {
		struct rpmi_perf_domain *domain = &mpxy_perf->domain[i];

		domain->id = i;
		domain->mpxy_ctx = mpxy_ctx;
		domain->dev = dev;
		domain->perf = mpxy_perf;

		rpmi_perf_enumerate(mpxy_perf, domain);
	}

	rpmi_perf_cpufreq_driver.driver_data = mpxy_perf;

	ret = cpufreq_register_driver(&rpmi_perf_cpufreq_driver);
	if (ret) {
		dev_err(dev, "registering cpufreq failed, err: %d\n", ret);
		goto fail_free_channel;
	}

	dev_info(dev, "%d MPXY cpufreq domains registered\n", num_domains);
	dev_set_drvdata(dev, mpxy_perf);

	return 0;

fail_free_channel:
	mbox_free_channel(mpxy_ctx->chan);

	return ret;
}

static void rpmi_cpufreq_remove(struct platform_device *pdev)
{
	cpufreq_unregister_driver(&rpmi_perf_cpufreq_driver);
}

static const struct of_device_id rpmi_cpufreq_of_match[] = {
	{ .compatible = "riscv,rpmi-performance" },
	{ },
};

MODULE_DEVICE_TABLE(of, rpmi_cpufreq_of_match);

static struct platform_driver rpmi_cpufreq_platdrv = {
	.driver = {
		.name = "riscv-rpmi-performance",
		.of_match_table = rpmi_cpufreq_of_match,
	},
	.probe = rpmi_cpufreq_probe,
	.remove = rpmi_cpufreq_remove,
};

module_platform_driver(rpmi_cpufreq_platdrv);

MODULE_AUTHOR("Joshua Yeong <joshua.yeong@starfivetech.com>");
MODULE_DESCRIPTION("CPUFreq Driver based on SBI MPXY extension");
MODULE_LICENSE("GPL");
