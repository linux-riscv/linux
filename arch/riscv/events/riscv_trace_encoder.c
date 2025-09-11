// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_BASENAME ": " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "riscv_trace.h"

static const struct of_device_id riscv_trace_encoder_of_match[] = {
	{.compatible = "riscv_trace,encoder-controller", },
	{ },
};

int riscv_trace_encoder_init(void)
{
	struct riscv_trace_component *component;
	struct device_node *node, *child_node, *port_node;
	struct riscv_io_port *io_port;
	resource_size_t base, size;
	u32 reg[4];
	int port_nr;
	int ret;

	for_each_matching_node(node, riscv_trace_encoder_of_match) {
		if (!of_device_is_available(node)) {
			of_node_put(node);
			continue;
		}

		component = kzalloc(sizeof(*component), GFP_KERNEL);
		if (!component)
			return -ENOMEM;
		component->type = RISCV_TRACE_ENCODER;

		ret = of_property_read_u32_array(node, "reg", &reg[0], 4);
		if (ret) {
			pr_err("Failed to read 'reg'\n");
			of_node_put(node);
			return ret;
		}
		base = ((resource_size_t) reg[0] << 32) | reg[1];
		size = ((resource_size_t) reg[2] << 32) | reg[3];
		pr_info("base=0x%llx size=0x%llx\n", base, size);
		component->reg_base = (u64)ioremap(base, size);
		component->reg_size = size;
		pr_info("reg_base=0x%llx reg_size=0x%llx\n",
			component->reg_base, component->reg_size);

		ret =
		    of_property_read_u32(node, "cpu", &component->encoder.cpu);
		if (ret) {
			pr_err("Failed to read 'cpu'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("cpu=%d\n", component->encoder.cpu);

		child_node = of_get_child_by_name(node, "output_port");
		if (!child_node) {
			pr_err("Failed to find 'output_port'\n");
			of_node_put(node);
			return -ENODEV;
		}
		component->out_num = count_device_node_child(child_node);
		if (component->out_num) {
			component->out =
			    krealloc_array(component->out, component->out_num,
					   sizeof(*component->out), GFP_KERNEL);
			if (!component->out)
				return -ENOMEM;
			port_nr = 0;

			for_each_child_of_node(child_node, port_node) {
				if (!of_device_is_available(port_node)) {
					of_node_put(child_node);
					continue;
				}
				pr_info("Found output_port: %pOF\n", port_node);
				const struct device_node *endpoint_node =
				    of_parse_phandle(port_node, "endpoint", 0);
				pr_info("\t endpoint: %pOF\n", endpoint_node);

				of_property_read_u32_array((struct device_node
							    *)endpoint_node,
							   "reg", &reg[0], 4);

				io_port =
				    kmalloc(sizeof(struct riscv_io_port),
					    GFP_KERNEL);
				io_port->is_input = false;
				io_port->endpoint_num = port_nr;
				io_port->type = RISCV_TRACE_FUNNEL;
				io_port->base_addr =
				    ((u64) reg[0] << 32) | reg[1];
				component->out[port_nr] = io_port;
				port_nr++;
			}
		}

		INIT_LIST_HEAD(&component->list);
		list_add_tail(&component->list, &riscv_trace_controllers);
	}

	return ret;
}
