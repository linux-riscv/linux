/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * phy-provider.h -- Generic PHY provider API
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com
 *
 * Author: Kishon Vijay Abraham I <kishon@ti.com>
 */
#ifndef __PHY_PROVIDER_H
#define __PHY_PROVIDER_H

#include <linux/err.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/regulator/consumer.h>
#include <linux/phy/phy-props.h>

struct phy;

/**
 * struct phy_ops - set of function pointers for performing phy operations
 * @init: operation to be performed for initializing phy
 * @exit: operation to be performed while exiting
 * @power_on: powering on the phy
 * @power_off: powering off the phy
 * @set_mode: set the mode of the phy
 * @set_media: set the media type of the phy (optional)
 * @set_speed: set the speed of the phy (optional)
 * @reset: resetting the phy
 * @calibrate: calibrate the phy
 * @notify_phystate: notify and configure the phy for a particular state
 * @release: ops to be performed while the consumer relinquishes the PHY
 * @owner: the module owner containing the ops
 */
struct phy_ops {
	int	(*init)(struct phy *phy);
	int	(*exit)(struct phy *phy);
	int	(*power_on)(struct phy *phy);
	int	(*power_off)(struct phy *phy);
	int	(*set_mode)(struct phy *phy, enum phy_mode mode, int submode);
	int	(*set_media)(struct phy *phy, enum phy_media media);
	int	(*set_speed)(struct phy *phy, int speed);

	/**
	 * @configure:
	 *
	 * Optional.
	 *
	 * Used to change the PHY parameters. phy_init() must have
	 * been called on the phy.
	 *
	 * Returns: 0 if successful, an negative error code otherwise
	 */
	int	(*configure)(struct phy *phy, union phy_configure_opts *opts);

	/**
	 * @validate:
	 *
	 * Optional.
	 *
	 * Used to check that the current set of parameters can be
	 * handled by the phy. Implementations are free to tune the
	 * parameters passed as arguments if needed by some
	 * implementation detail or constraints. It must not change
	 * any actual configuration of the PHY, so calling it as many
	 * times as deemed fit by the consumer must have no side
	 * effect.
	 *
	 * Returns: 0 if the configuration can be applied, an negative
	 * error code otherwise
	 */
	int	(*validate)(struct phy *phy, enum phy_mode mode, int submode,
			    union phy_configure_opts *opts);
	int	(*reset)(struct phy *phy);
	int	(*calibrate)(struct phy *phy);

	/* notify phy connect status change */
	int	(*connect)(struct phy *phy, int port);
	int	(*disconnect)(struct phy *phy, int port);

	int	(*notify_phystate)(struct phy *phy, union phy_notify state);
	void	(*release)(struct phy *phy);
	struct module *owner;
};

/**
 * struct phy_attrs - represents phy attributes
 * @bus_width: Data path width implemented by PHY
 * @max_link_rate: Maximum link rate supported by PHY (units to be decided by producer and consumer)
 * @mode: PHY mode
 */
struct phy_attrs {
	u32			bus_width;
	u32			max_link_rate;
	enum phy_mode		mode;
};

/**
 * struct phy - represents the phy device
 * @dev: phy device
 * @id: id of the phy device
 * @ops: function pointers for performing phy operations
 * @mutex: mutex to protect phy_ops
 * @lockdep_key: lockdep information for this mutex
 * @init_count: used to protect when the PHY is used by multiple consumers
 * @power_count: used to protect when the PHY is used by multiple consumers
 * @attrs: used to specify PHY specific attributes
 * @pwr: power regulator associated with the phy
 * @debugfs: debugfs directory
 */
struct phy {
	struct device		dev;
	int			id;
	const struct phy_ops	*ops;
	struct mutex		mutex;
	struct lock_class_key	lockdep_key;
	int			init_count;
	int			power_count;
	struct phy_attrs	attrs;
	struct regulator	*pwr;
	struct dentry		*debugfs;
};

/**
 * struct phy_provider - represents the phy provider
 * @dev: phy provider device
 * @children: can be used to override the default (dev->of_node) child node
 * @owner: the module owner having of_xlate
 * @list: to maintain a linked list of PHY providers
 * @of_xlate: function pointer to obtain phy instance from phy pointer
 */
struct phy_provider {
	struct device		*dev;
	struct device_node	*children;
	struct module		*owner;
	struct list_head	list;
	struct phy *(*of_xlate)(struct device *dev,
				const struct of_phandle_args *args);
};

#define	of_phy_provider_register(dev, xlate)	\
	__of_phy_provider_register((dev), NULL, THIS_MODULE, (xlate))

#define	devm_of_phy_provider_register(dev, xlate)	\
	__devm_of_phy_provider_register((dev), NULL, THIS_MODULE, (xlate))

#define of_phy_provider_register_full(dev, children, xlate) \
	__of_phy_provider_register(dev, children, THIS_MODULE, xlate)

#define devm_of_phy_provider_register_full(dev, children, xlate) \
	__devm_of_phy_provider_register(dev, children, THIS_MODULE, xlate)

static inline void phy_set_drvdata(struct phy *phy, void *data)
{
	dev_set_drvdata(&phy->dev, data);
}

static inline void *phy_get_drvdata(struct phy *phy)
{
	return dev_get_drvdata(&phy->dev);
}

#if IS_ENABLED(CONFIG_GENERIC_PHY)
struct phy *phy_create(struct device *dev, struct device_node *node,
		       const struct phy_ops *ops);
struct phy *devm_phy_create(struct device *dev, struct device_node *node,
			    const struct phy_ops *ops);
void phy_destroy(struct phy *phy);
void devm_phy_destroy(struct device *dev, struct phy *phy);

struct phy_provider *
__of_phy_provider_register(struct device *dev, struct device_node *children,
			   struct module *owner,
			   struct phy *(*of_xlate)(struct device *dev,
						   const struct of_phandle_args *args));
struct phy_provider *
__devm_of_phy_provider_register(struct device *dev, struct device_node *children,
				struct module *owner,
				struct phy *(*of_xlate)(struct device *dev,
							const struct of_phandle_args *args));
void of_phy_provider_unregister(struct phy_provider *phy_provider);
void devm_of_phy_provider_unregister(struct device *dev,
				     struct phy_provider *phy_provider);
int phy_create_lookup(struct phy *phy, const char *con_id, const char *dev_id);
void phy_remove_lookup(struct phy *phy, const char *con_id, const char *dev_id);
struct phy *of_phy_simple_xlate(struct device *dev,
				const struct of_phandle_args *args);
#else
static inline struct phy *phy_create(struct device *dev,
				     struct device_node *node,
				     const struct phy_ops *ops)
{
	return ERR_PTR(-ENOSYS);
}

static inline struct phy *devm_phy_create(struct device *dev,
					  struct device_node *node,
					  const struct phy_ops *ops)
{
	return ERR_PTR(-ENOSYS);
}

static inline void phy_destroy(struct phy *phy)
{
}

static inline void devm_phy_destroy(struct device *dev, struct phy *phy)
{
}

static inline struct phy_provider *
__of_phy_provider_register(struct device *dev, struct device_node *children,
			   struct module *owner,
			   struct phy *(*of_xlate)(struct device *dev,
						   const struct of_phandle_args *args))
{
	return ERR_PTR(-ENOSYS);
}

static inline struct phy_provider *
__devm_of_phy_provider_register(struct device *dev, struct device_node *children,
				struct module *owner,
				struct phy *(*of_xlate)(struct device *dev,
							const struct of_phandle_args *args))
{
	return ERR_PTR(-ENOSYS);
}

static inline void of_phy_provider_unregister(struct phy_provider *phy_provider)
{
}

static inline void devm_of_phy_provider_unregister(struct device *dev,
						   struct phy_provider *phy_provider)
{
}

static inline int phy_create_lookup(struct phy *phy, const char *con_id,
				    const char *dev_id)
{
	return 0;
}

static inline void phy_remove_lookup(struct phy *phy, const char *con_id,
				     const char *dev_id)
{
}

static inline struct phy *of_phy_simple_xlate(struct device *dev,
					      const struct of_phandle_args *args)
{
	return ERR_PTR(-ENOSYS);
}
#endif /* IS_ENABLED(CONFIG_GENERIC_PHY) */

#endif /* __PHY_PROVIDER_H */
