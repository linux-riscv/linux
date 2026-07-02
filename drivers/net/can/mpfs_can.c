// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Microchip Polarfire SoC MSS CAN controller driver
 *
 * Copyright (C) 2023 Microchip Technology Inc. and its subsidiaries
 *
 * Author: Naga Sureshkumar Relli <nagasuresh.relli@microchip.com>
 *
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/can/dev.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#define MPFS_CAN_ISR_OFFSET		0x00
#define MPFS_CAN_IER_OFFSET		0x04
#define MPFS_CAN_RXBUF_STAT_OFFSET	0x08
#define MPFS_CAN_TXBUF_STAT_OFFSET	0x0c
#define MPFS_CAN_ESR_OFFSET		0x10
#define MPFS_CAN_COMMAND_OFFSET		0x14
#define MPFS_CAN_CONFIG_OFFSET		0x18
#define MPFS_CAN_TX_MSG_CTRL_CMD_BASE	0x20
#define MPFS_CAN_TX_MSG_ID_BASE		0x24
#define MPFS_CAN_TX_MSG_DATAL_BASE	0x28
#define MPFS_CAN_TX_MSG_DATAH_BASE	0x2c
#define MPFS_CAN_RX_MSG_CTRL_CMD_BASE	0x220
#define MPFS_CAN_RX_MSG_ID_BASE		0x224
#define MPFS_CAN_RX_MSG_DATAL_BASE	0x228
#define MPFS_CAN_RX_MSG_DATAH_BASE	0x22c
#define MPFS_CAN_RX_MSG_AMR_BASE	0x230
#define MPFS_CAN_RX_MSG_ACR_BASE	0x234
#define MPFS_CAN_RX_MSG_AMR_DATA_BASE	0x238
#define MPFS_CAN_RX_MSG_ACR_DATA_BASE	0x23c

#define MPFS_CAN_ISR_ARB_LOSS_MASK	BIT(2)
#define MPFS_CAN_ISR_OVR_LOAD_MASK	BIT(3)
#define MPFS_CAN_ISR_BIT_ERR_MASK	BIT(4)
#define MPFS_CAN_ISR_STUFF_ERR_MASK	BIT(5)
#define MPFS_CAN_ISR_ACK_ERR_MASK	BIT(6)
#define MPFS_CAN_ISR_FORM_ERR_MASK	BIT(7)
#define MPFS_CAN_ISR_CRC_ERR_MASK	BIT(8)
#define MPFS_CAN_ISR_BUS_OFF_MASK	BIT(9)
#define MPFS_CAN_ISR_TXMSG_SNT_MASK	BIT(11)
#define MPFS_CAN_ISR_RXMSG_SNT_MASK	BIT(12)

#define MPFS_CAN_ERR_MASK	(MPFS_CAN_ISR_ARB_LOSS_MASK | \
				 MPFS_CAN_ISR_BIT_ERR_MASK | \
				 MPFS_CAN_ISR_STUFF_ERR_MASK | \
				 MPFS_CAN_ISR_ACK_ERR_MASK | \
				 MPFS_CAN_ISR_FORM_ERR_MASK | \
				 MPFS_CAN_ISR_CRC_ERR_MASK | \
				 MPFS_CAN_ISR_OVR_LOAD_MASK | \
				 MPFS_CAN_ISR_BUS_OFF_MASK)

#define MPFS_CAN_IER_GLOBAL_MASK	BIT(0)
#define MPFS_CAN_IER_ARB_LOSS_MASK	BIT(2)
#define MPFS_CAN_IER_OVR_LOAD_MASK	BIT(3)
#define MPFS_CAN_IER_BIT_ERR_MASK	BIT(4)
#define MPFS_CAN_IER_STUFF_ERR_MASK	BIT(5)
#define MPFS_CAN_IER_ACK_ERR_MASK	BIT(6)
#define MPFS_CAN_IER_FORM_ERR_MASK	BIT(7)
#define MPFS_CAN_IER_CRC_ERR_MASK	BIT(8)
#define MPFS_CAN_IER_BUS_OFF_MASK	BIT(9)
#define MPFS_CAN_IER_RXMSG_LOS_MASK	BIT(10)
#define MPFS_CAN_IER_TXMSG_SNT_MASK	BIT(11)
#define MPFS_CAN_IER_RXMSG_SNT_MASK	BIT(12)
#define MPFS_CAN_IER_RTR_SNT_MASK	BIT(13)

#define MPFS_CAN_IER_MASK	(MPFS_CAN_IER_ARB_LOSS_MASK | \
				 MPFS_CAN_IER_BIT_ERR_MASK | \
				 MPFS_CAN_IER_STUFF_ERR_MASK | \
				 MPFS_CAN_IER_ACK_ERR_MASK | \
				 MPFS_CAN_IER_FORM_ERR_MASK | \
				 MPFS_CAN_IER_CRC_ERR_MASK | \
				 MPFS_CAN_IER_BUS_OFF_MASK | \
				 MPFS_CAN_IER_RXMSG_LOS_MASK | \
				 MPFS_CAN_IER_TXMSG_SNT_MASK | \
				 MPFS_CAN_IER_RXMSG_SNT_MASK | \
				 MPFS_CAN_IER_RTR_SNT_MASK | \
				 MPFS_CAN_IER_OVR_LOAD_MASK | \
				 MPFS_CAN_IER_GLOBAL_MASK)

#define MPFS_CAN_ERR_TXCNT_MASK		GENMASK(7, 0)
#define MPFS_CAN_ERR_RXCNT_MASK		GENMASK(15, 8)
#define MPFS_CAN_ERR_PASSIVE_MASK	BIT(16)
#define MPFS_CAN_ERR_BUS_OFF_MASK	BIT(17)
#define MPFS_CAN_ERR_TX96_MASK		BIT(18)
#define MPFS_CAN_ERR_RX96_MASK		BIT(19)
#define MPFS_CAN_ERR_RXCNT_SHIFT	8

#define MPFS_CAN_CMD_NORMAL_MASK	BIT(0)
#define MPFS_CAN_CMD_LOOP_MASK		GENMASK(2, 0)

#define MPFS_CAN_CONFIG_CFG_SJW_MASK	GENMASK(3, 2)
#define MPFS_CAN_CONFIG_TSEG2_MASK	GENMASK(7, 5)
#define MPFS_CAN_CONFIG_TSEG1_MASK	GENMASK(11, 8)
#define MPFS_CAN_CONFIG_BITR_MASK	GENMASK(30, 16)

#define MPFS_CAN_TXMSG_CTRL_CMD_TXREQ_MASK	BIT(0)
#define MPFS_CAN_TXMSG_CTRL_CMD_TXINTEN_MASK	BIT(2)
#define MPFS_CAN_TXMSG_CTRL_CMD_WPNA_MASK	BIT(3)
#define MPFS_CAN_TXMSG_CTRL_CMD_DLC_MASK	GENMASK(19, 16)
#define MPFS_CAN_TXMSG_CTRL_CMD_IDE_MASK	BIT(20)
#define MPFS_CAN_TXMSG_CTRL_CMD_RTR_MASK	BIT(21)
#define MPFS_CAN_TXMSG_CTRL_CMD_WPNB_MASK	BIT(23)

#define MPFS_CAN_RXMSG_CTRL_CMD_AVAIL_MASK	BIT(0)
#define MPFS_CAN_RXMSG_CTRL_CMD_BUFEN_MASK	BIT(3)
#define MPFS_CAN_RXMSG_CTRL_CMD_RXINTEN_MASK	BIT(5)
#define MPFS_CAN_RXMSG_CTRL_CMD_LF_MASK		BIT(6)
#define MPFS_CAN_RXMSG_CTRL_CMD_WPNL_MASK	BIT(7)
#define MPFS_CAN_RXMSG_CTRL_CMD_DLC_MASK	GENMASK(19, 16)
#define MPFS_CAN_RXMSG_CTRL_CMD_IDE_MASK	BIT(20)
#define MPFS_CAN_RXMSG_CTRL_CMD_RTR_MASK	BIT(21)
#define MPFS_CAN_RXMSG_CTRL_CMD_WPNH_MASK	BIT(23)

#define MPFS_CAN_BTR_SJW_MASK	GENMASK(3, 2)
#define MPFS_CAN_BTR_MASK	GENMASK(30, 16)
#define MPFS_CAN_DLC_MASK	GENMASK(19, 16)
#define MPFS_CAN_TS1_MASK	GENMASK(11, 8)
#define MPFS_CAN_TS2_MASK	GENMASK(7, 5)
#define MPFS_CAN_STDID_SHIFT	21
#define MPFS_CAN_EXTID_SHIFT	3

#define MPFS_CAN_TX_REG_LEN	16
#define MPFS_CAN_RX_REG_LEN	32

#define MPFS_CAN_TX_MSG_BASE(base, fifo)	((base) + ((fifo) * MPFS_CAN_TX_REG_LEN))
#define MPFS_CAN_RX_MSG_BASE(base, fifo)	((base) + ((fifo) * MPFS_CAN_RX_REG_LEN))

#define MPFS_CAN_TX_MSG_CTR_OFFSET(fifo)	MPFS_CAN_TX_MSG_BASE(MPFS_CAN_TX_MSG_CTRL_CMD_BASE, fifo)
#define MPFS_CAN_TX_MSG_ID_OFFSET(fifo)		MPFS_CAN_TX_MSG_BASE(MPFS_CAN_TX_MSG_ID_BASE, fifo)
#define MPFS_CAN_TX_DATAL_OFFSET(fifo)		MPFS_CAN_TX_MSG_BASE(MPFS_CAN_TX_MSG_DATAL_BASE, fifo)
#define MPFS_CAN_TX_DATAH_OFFSET(fifo)		MPFS_CAN_TX_MSG_BASE(MPFS_CAN_TX_MSG_DATAH_BASE, fifo)

#define MPFS_CAN_RX_MSG_CTR_OFFSET(fifo)	MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_CTRL_CMD_BASE, fifo)
#define MPFS_CAN_RX_MSG_ID_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_ID_BASE, fifo)
#define MPFS_CAN_RX_DATAL_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_DATAL_BASE, fifo)
#define MPFS_CAN_RX_DATAH_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_DATAH_BASE, fifo)
#define MPFS_CAN_AMR_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_AMR_BASE, fifo)
#define MPFS_CAN_ACR_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_ACR_BASE, fifo)
#define MPFS_CAN_AMR_DATA_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_AMR_DATA_BASE, fifo)
#define MPFS_CAN_ACR_DATA_OFFSET(fifo)		MPFS_CAN_RX_MSG_BASE(MPFS_CAN_RX_MSG_ACR_DATA_BASE, fifo)

#define MPFS_CAN_TX_BUFFERS	32
#define MPFS_CAN_RX_BUFFERS	32
#define MPFS_CAN_AMR_MASK	GENMASK(31, 0)
#define MPFS_CAN_AMR_DATA_MASK	GENMASK(31, 0)

struct mpfs_can_priv {
	struct can_priv can;
	struct napi_struct napi;
	struct device *dev;
	void __iomem *base;
	struct clk_bulk_data *clks;
	const struct can_bittiming_const *bittiming_const;
	spinlock_t tx_lock;
	unsigned long irq_flags;
	unsigned int tx_head;
	unsigned int tx_tail;
	unsigned int tx_max;
	int num_clocks;
};

static const struct can_bittiming_const mpfs_can_bittiming_const = {
	.name = "mpfs_can",
	.tseg1_min = 2,
	.tseg1_max = 16,
	.tseg2_min = 1,
	.tseg2_max = 8,
	.sjw_max = 4,
	.brp_min = 0,
	.brp_max = 32767,
	.brp_inc = 1,
};

static int mpfs_can_reset(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int ret;

	/* There is no separate register in the MSS CAN to do the soft reset
	 * hence do the full device reset and this is needed to bring back the
	 * bus to normal state in error cases.
	 */
	ret = device_reset(priv->dev);
	if (ret)
		return ret;

	priv->tx_head = 0;
	priv->tx_tail = 0;

	return 0;
}

static int mpfs_can_set_bittiming(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	struct can_bittiming *bt = &priv->can.bittiming;
	u32 config, can_started;

	can_started = readl(priv->base + MPFS_CAN_COMMAND_OFFSET) & MPFS_CAN_CMD_NORMAL_MASK;
	if (can_started) {
		netdev_alert(ndev,
			     "BUG! Cannot set bittiming - CAN is already running\n");
		return -EPERM;
	}

	/* The TS1, TS2 and buad rate values written in the Config register are
	 * added to 1 to compute the prescalar.
	 * TS1 configuration for the mpfs can includes both propagation seg and phase seg1
	 */
	config = FIELD_PREP(MPFS_CAN_BTR_MASK, bt->brp - 1) |
		 FIELD_PREP(MPFS_CAN_TS1_MASK, bt->prop_seg + bt->phase_seg1 - 1) |
		 FIELD_PREP(MPFS_CAN_TS2_MASK, bt->phase_seg2 - 1) |
		 FIELD_PREP(MPFS_CAN_BTR_SJW_MASK, bt->sjw - 1);

	writel(config, priv->base + MPFS_CAN_CONFIG_OFFSET);

	return 0;
}

static int mpfs_can_start(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int ret, buf;
	u32 val;

	//TODO this means that the device is reset twice on setting the device
	//"up" with ip link. Is that excessive? Could we get away with only
	//resetting in mpfs_can_open() instead of mpfs_can_start()?
	ret = mpfs_can_reset(ndev);
	if (ret)
		return ret;

	ret = mpfs_can_set_bittiming(ndev);
	if (ret < 0)
		return ret;

	/* Clear pending interrupts */
	writel(0x0, priv->base + MPFS_CAN_ISR_OFFSET);

	/* Enable interrupts */
	writel(MPFS_CAN_IER_MASK, priv->base + MPFS_CAN_IER_OFFSET);

	if (priv->can.ctrlmode & CAN_CTRLMODE_LOOPBACK)
		val = MPFS_CAN_CMD_LOOP_MASK;
	else
		val = MPFS_CAN_CMD_NORMAL_MASK;

	writel(val, priv->base + MPFS_CAN_COMMAND_OFFSET);

	for (buf = 0; buf < MPFS_CAN_RX_BUFFERS; buf++)	{
		writel(MPFS_CAN_AMR_MASK, priv->base + MPFS_CAN_AMR_OFFSET(buf));
		writel(0x0, priv->base + MPFS_CAN_ACR_OFFSET(buf));

		writel(MPFS_CAN_AMR_DATA_MASK, priv->base + MPFS_CAN_AMR_DATA_OFFSET(buf));
		writel(0x0, priv->base + MPFS_CAN_ACR_DATA_OFFSET(buf));

		/* Enable the link flag for the buffers, so that the receive data will store
		 * in sequential order, except for the last buffer.
		 */
		val = MPFS_CAN_RXMSG_CTRL_CMD_WPNL_MASK | MPFS_CAN_RXMSG_CTRL_CMD_WPNH_MASK |
		      MPFS_CAN_RXMSG_CTRL_CMD_BUFEN_MASK | MPFS_CAN_RXMSG_CTRL_CMD_RXINTEN_MASK;

		if (buf != (MPFS_CAN_RX_BUFFERS - 1))
			val |= MPFS_CAN_RXMSG_CTRL_CMD_LF_MASK;

		writel(val, priv->base + MPFS_CAN_RX_MSG_CTR_OFFSET(buf));
	}

	priv->can.state = CAN_STATE_ERROR_ACTIVE;

	return 0;
}

static int mpfs_can_do_set_mode(struct net_device *ndev, enum can_mode mode)
{
	int ret;

	switch (mode) {
	case CAN_MODE_START:

		ret = mpfs_can_start(ndev);
		if (ret < 0) {
			netdev_err(ndev, "mpfs_can_start() failed!\n");
			return ret;
		}

		netif_wake_queue(ndev);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static void mpfs_can_tx(struct net_device *ndev, struct sk_buff *skb,
			int buf_off)
{
	struct can_frame *frame = (struct can_frame *)skb->data;
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	u32 id = 0, data[2] = {0, 0}, ctlr = 0;

	if (frame->can_id & CAN_EFF_FLAG) {
		ctlr = MPFS_CAN_TXMSG_CTRL_CMD_IDE_MASK;
		id = (frame->can_id << MPFS_CAN_EXTID_SHIFT);
	} else {
		id = (frame->can_id << MPFS_CAN_STDID_SHIFT);
	}

	if (frame->can_id & CAN_RTR_FLAG)
		ctlr |= MPFS_CAN_TXMSG_CTRL_CMD_RTR_MASK;

	ctlr |= FIELD_PREP(MPFS_CAN_DLC_MASK, frame->len) |
		MPFS_CAN_TXMSG_CTRL_CMD_WPNA_MASK | MPFS_CAN_TXMSG_CTRL_CMD_WPNB_MASK |
		MPFS_CAN_TXMSG_CTRL_CMD_TXREQ_MASK | MPFS_CAN_TXMSG_CTRL_CMD_TXINTEN_MASK;
	can_put_echo_skb(skb, ndev, priv->tx_head % priv->tx_max, 0);

	priv->tx_head++;
	writel(id, priv->base + MPFS_CAN_TX_MSG_ID_OFFSET(buf_off));

	if (frame->len > 0)
		data[0] = be32_to_cpup((__be32 *)(frame->data + 0));

	if (frame->len > 4)
		data[1] = be32_to_cpup((__be32 *)(frame->data + 4));

	if (!(frame->can_id & CAN_RTR_FLAG)) {
		writel(data[0], priv->base + MPFS_CAN_TX_DATAL_OFFSET(buf_off));
		writel(data[1], priv->base + MPFS_CAN_TX_DATAH_OFFSET(buf_off));
	}

	writel(ctlr, priv->base + MPFS_CAN_TX_MSG_CTR_OFFSET(buf_off));
}

static int mpfs_can_get_txmsg_index(struct mpfs_can_priv *priv)
{
	for (int buf_index = 0; buf_index < MPFS_CAN_TX_BUFFERS; buf_index++) {
		int available_txreq;

		available_txreq = readl(priv->base + MPFS_CAN_TX_MSG_CTR_OFFSET(buf_index));

		if (available_txreq & MPFS_CAN_TXMSG_CTRL_CMD_TXREQ_MASK)
			continue;

		return buf_index;
	}

	return -ENOBUFS;
}

static int mpfs_can_get_rxmsg_index(struct mpfs_can_priv *priv)
{
	for (int buf_index = 0; buf_index < MPFS_CAN_RX_BUFFERS; buf_index++) {
		int available_rxreq;

		available_rxreq = readl(priv->base + MPFS_CAN_RX_MSG_CTR_OFFSET(buf_index));

		if (!(available_rxreq & MPFS_CAN_RXMSG_CTRL_CMD_AVAIL_MASK))
			continue;

		return buf_index;
	}

	return -ENOBUFS;
}

static netdev_tx_t mpfs_can_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int buf_off;
	unsigned long flags;

	if (can_dropped_invalid_skb(ndev, skb))
		return NETDEV_TX_OK;

	buf_off = mpfs_can_get_txmsg_index(priv);
	if (buf_off < 0) {
		netdev_err(ndev, "BUG!, TX full when queue awake!\n");
		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	spin_lock_irqsave(&priv->tx_lock, flags);
	mpfs_can_tx(ndev, skb, buf_off);

	if ((priv->tx_head - priv->tx_tail) == priv->tx_max)
		netif_stop_queue(ndev);

	netif_stop_queue(ndev);

	spin_unlock_irqrestore(&priv->tx_lock, flags);

	return NETDEV_TX_OK;
}

static int mpfs_can_rx(struct net_device *ndev, int buf_off)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	struct can_frame *frame;
	struct sk_buff *skb;
	u32 data[2] = {0, 0};
	u32 id, ctrl;

	skb = alloc_can_skb(ndev, &frame);
	if (unlikely(!skb)) {
		stats->rx_dropped++;
		return 0;
	}

	id = readl(priv->base + MPFS_CAN_RX_MSG_ID_OFFSET(buf_off));
	ctrl = readl(priv->base + MPFS_CAN_RX_MSG_CTR_OFFSET(buf_off));

	if (ctrl & MPFS_CAN_RXMSG_CTRL_CMD_IDE_MASK) {
		frame->can_id = CAN_EFF_FLAG;
		frame->can_id |= (id >> MPFS_CAN_EXTID_SHIFT);
	} else {
		frame->can_id = (id >> MPFS_CAN_STDID_SHIFT);
	}

	if (ctrl & MPFS_CAN_RXMSG_CTRL_CMD_RTR_MASK)
		frame->can_id |= CAN_RTR_FLAG;

	frame->len = (ctrl & MPFS_CAN_DLC_MASK) >> 16;

	data[0] = readl(priv->base + MPFS_CAN_RX_DATAL_OFFSET(buf_off));
	data[1] = readl(priv->base + MPFS_CAN_RX_DATAH_OFFSET(buf_off));

	if (!(frame->can_id & CAN_RTR_FLAG)) {
		if (frame->len > 0)
			*(__be32 *)(frame->data) = cpu_to_be32(data[0]);

		if (frame->len > 4)
			*(__be32 *)(frame->data + 4) = cpu_to_be32(data[1]);
	}

	/* Notify the controller that the rx message is read by writing the
	 * message available bit.
	 */
	ctrl = readl(priv->base + MPFS_CAN_RX_MSG_CTR_OFFSET(buf_off));
	ctrl |= MPFS_CAN_RXMSG_CTRL_CMD_AVAIL_MASK;
	writel(ctrl, priv->base + MPFS_CAN_RX_MSG_CTR_OFFSET(buf_off));

	stats->rx_bytes += frame->len;
	stats->rx_packets++;
	netif_receive_skb(skb);

	return 1;
}

static enum can_state mpfs_can_current_error_state(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	u32 status;

	status = readl(priv->base + MPFS_CAN_ESR_OFFSET);

	if (status & MPFS_CAN_ERR_BUS_OFF_MASK)
		return CAN_STATE_BUS_OFF;
	else if (status & MPFS_CAN_ERR_PASSIVE_MASK)
		return CAN_STATE_ERROR_PASSIVE;
	else if (status & (MPFS_CAN_ERR_TX96_MASK | MPFS_CAN_ERR_RX96_MASK))
		return CAN_STATE_ERROR_WARNING;
	else
		return CAN_STATE_ERROR_ACTIVE;
}

static void mpfs_can_set_error_state(struct net_device *ndev, enum can_state new_state,
				     struct can_frame *frame)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	enum can_state tx_state, rx_state;
	u32 ecr, txerr, rxerr;

	ecr = readl(priv->base + MPFS_CAN_ESR_OFFSET);
	txerr = ecr & MPFS_CAN_ERR_TXCNT_MASK;
	rxerr = (ecr & MPFS_CAN_ERR_RXCNT_MASK) >> MPFS_CAN_ERR_RXCNT_SHIFT;

	tx_state = txerr >= rxerr ? new_state : 0;
	rx_state = txerr <= rxerr ? new_state : 0;

	if (new_state > CAN_STATE_ERROR_PASSIVE) {
		frame->can_id |= CAN_ERR_CRTL;
		frame->data[1] = (txerr > rxerr) ?
				  CAN_ERR_CRTL_TX_PASSIVE : CAN_ERR_CRTL_RX_PASSIVE;
	} else {
		can_change_state(ndev, frame, tx_state, rx_state);

		if (frame) {
			frame->data[6] = txerr;
			frame->data[7] = rxerr;
		}
	}
}

static void mpfs_can_update_error_state(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	enum can_state old_state = priv->can.state;
	enum can_state new_state;

	if (old_state != CAN_STATE_ERROR_WARNING &&
	    old_state != CAN_STATE_ERROR_PASSIVE)
		return;

	new_state = mpfs_can_current_error_state(ndev);

	if (new_state != old_state) {
		struct sk_buff *skb;
		struct can_frame *cf;

		skb = alloc_can_err_skb(ndev, &cf);

		mpfs_can_set_error_state(ndev, new_state, skb ? cf : NULL);

		if (skb) {
			struct net_device_stats *stats = &ndev->stats;

			stats->rx_packets++;
			stats->rx_bytes += cf->len;
			netif_rx(skb);
		}
	}
}

static void mpfs_can_err_interrupt(struct net_device *ndev, u32 int_status)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	struct can_frame cf = { };
	u32 err_status;

	err_status = readl(priv->base + MPFS_CAN_ESR_OFFSET);

	if (int_status & MPFS_CAN_ISR_BUS_OFF_MASK) {
		priv->can.state = CAN_STATE_BUS_OFF;
		priv->can.can_stats.bus_off++;
		can_bus_off(ndev);
		cf.can_id |= CAN_ERR_BUSOFF;
	} else {
		enum can_state new_state = mpfs_can_current_error_state(ndev);

		if (new_state != priv->can.state)
			mpfs_can_set_error_state(ndev, new_state, &cf);
	}

	if (int_status & MPFS_CAN_ISR_ARB_LOSS_MASK) {
		priv->can.can_stats.arbitration_lost++;
		cf.can_id |= CAN_ERR_LOSTARB;
		cf.data[0] = CAN_ERR_LOSTARB_UNSPEC;
	}

	if (int_status & MPFS_CAN_ERR_MASK) {
		priv->can.can_stats.bus_error++;
		cf.can_id |= CAN_ERR_PROT | CAN_ERR_BUSERROR;

		if (int_status & MPFS_CAN_ISR_ACK_ERR_MASK) {
			stats->tx_errors++;
			cf.can_id |= CAN_ERR_ACK;
			cf.data[3] = CAN_ERR_PROT_LOC_ACK;
		}

		if (int_status & MPFS_CAN_ISR_BIT_ERR_MASK) {
			stats->tx_errors++;
			cf.can_id |= CAN_ERR_PROT;
			cf.data[2] |= CAN_ERR_PROT_BIT;
		}

		if (int_status & MPFS_CAN_ISR_STUFF_ERR_MASK) {
			stats->rx_errors++;
			cf.can_id |= CAN_ERR_PROT;
			cf.data[2] |= CAN_ERR_PROT_STUFF;
		}

		if (err_status & MPFS_CAN_ISR_FORM_ERR_MASK) {
			stats->rx_errors++;
			cf.can_id |= CAN_ERR_PROT;
			cf.data[2] |= CAN_ERR_PROT_FORM;
		}

		if (err_status & MPFS_CAN_ISR_CRC_ERR_MASK) {
			stats->rx_errors++;
			cf.can_id |= CAN_ERR_PROT;
			cf.data[3] |= CAN_ERR_PROT_LOC_CRC_SEQ;
		}

		if (err_status & MPFS_CAN_ISR_OVR_LOAD_MASK) {
			stats->rx_over_errors++;
			stats->rx_errors++;
			cf.can_id |= CAN_ERR_PROT;
			cf.data[3] |= CAN_ERR_PROT_OVERLOAD;
		}
	}

	if (cf.can_id) {
		struct can_frame *frame;
		struct sk_buff *skb = alloc_can_err_skb(ndev, &frame);

		if (skb) {
			frame->can_id |= cf.can_id;
			memcpy(frame->data, cf.data, CAN_ERR_DLC);
			stats->rx_packets++;
			stats->rx_bytes += CAN_ERR_DLC;
			netif_rx(skb);
		}
	}

	netdev_dbg(ndev, "error status register:0x%x\n", err_status);
}

static int mpfs_can_rx_poll(struct napi_struct *napi, int quota)
{
	struct net_device *ndev = napi->dev;
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int processed = 0, buf_off;
	u32 int_enable;

	while ((buf_off = mpfs_can_get_rxmsg_index(priv)) >= 0 && (processed < quota))
		processed += mpfs_can_rx(ndev, buf_off);

	if (processed)
		mpfs_can_update_error_state(ndev);

	if (processed < quota) {
		if (napi_complete_done(napi, processed)) {
			int_enable = readl(priv->base + MPFS_CAN_IER_OFFSET);
			int_enable |= (MPFS_CAN_IER_RXMSG_SNT_MASK);
			writel(int_enable, priv->base + MPFS_CAN_IER_OFFSET);
		}
	}

	return processed;
}

static void mpfs_can_tx_interrupt(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	unsigned int frames_in_fifo;
	unsigned long flags;
	int bytes = 0;

	spin_lock_irqsave(&priv->tx_lock, flags);
	frames_in_fifo = priv->tx_head - priv->tx_tail;

	while (frames_in_fifo--) {
		bytes = can_get_echo_skb(ndev, priv->tx_tail % priv->tx_max, NULL);
		stats->tx_bytes += bytes;
		priv->tx_tail++;
		stats->tx_packets++;
	}

	netif_wake_queue(ndev);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	mpfs_can_update_error_state(ndev);
}

static irqreturn_t mpfs_can_interrupt(int irq, void *dev_id)
{
	struct net_device *ndev = (struct net_device *)dev_id;
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	u32 isr, ier;

	isr = readl(priv->base + MPFS_CAN_ISR_OFFSET);
	if (!isr)
		return IRQ_NONE;

	writel(isr, priv->base + MPFS_CAN_ISR_OFFSET);

	if (isr & MPFS_CAN_ISR_TXMSG_SNT_MASK)
		mpfs_can_tx_interrupt(ndev);

	if (isr & MPFS_CAN_ERR_MASK)
		mpfs_can_err_interrupt(ndev, isr);

	if (isr & MPFS_CAN_ISR_RXMSG_SNT_MASK) {
		ier = readl(priv->base + MPFS_CAN_IER_OFFSET);
		ier &= ~(MPFS_CAN_IER_RXMSG_SNT_MASK | MPFS_CAN_IER_RTR_SNT_MASK);
		writel(ier, priv->base + MPFS_CAN_IER_OFFSET);
		napi_schedule(&priv->napi);
	}

	return IRQ_HANDLED;
}

static int mpfs_can_chip_stop(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int ret;

	ret = mpfs_can_reset(ndev);
	if (ret)
		return ret;

	priv->can.state = CAN_STATE_STOPPED;

	return 0;
}

static int mpfs_can_open(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int ret;

	ret = request_irq(ndev->irq, mpfs_can_interrupt, priv->irq_flags,
			  ndev->name, ndev);
	if (ret < 0) {
		netdev_err(ndev, "irq allocation for CAN failed\n");
		return ret;
	}

	ret = mpfs_can_reset(ndev);
	if (ret)
		goto err_irq;

	ret = open_candev(ndev);
	if (ret)
		goto err_irq;

	ret = mpfs_can_start(ndev);
	if (ret < 0) {
		netdev_err(ndev, "mpfs_can_start() failed!\n");
		goto err_candev;
	}

	napi_enable(&priv->napi);
	netif_start_queue(ndev);

	return 0;

err_candev:
	close_candev(ndev);
err_irq:
	free_irq(ndev->irq, ndev);

	return ret;
}

static int mpfs_can_close(struct net_device *ndev)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int ret;

	netif_stop_queue(ndev);
	napi_disable(&priv->napi);
	ret = mpfs_can_chip_stop(ndev);
	free_irq(ndev->irq, ndev);
	close_candev(ndev);

	return ret;
}

static int mpfs_can_get_berr_counter(const struct net_device *ndev,
				     struct can_berr_counter *bec)
{
	struct mpfs_can_priv *priv = netdev_priv(ndev);
	int err_cnt;

	err_cnt = readl(priv->base + MPFS_CAN_ESR_OFFSET);
	bec->txerr = err_cnt & MPFS_CAN_ERR_TXCNT_MASK;
	bec->rxerr = (err_cnt & MPFS_CAN_ERR_RXCNT_MASK) >> MPFS_CAN_ERR_RXCNT_SHIFT;

	return 0;
}

static const struct net_device_ops mpfs_can_netdev_ops = {
	.ndo_open = mpfs_can_open,
	.ndo_stop = mpfs_can_close,
	.ndo_start_xmit	= mpfs_can_start_xmit,
};

static int mpfs_can_probe(struct platform_device *pdev)
{
	struct net_device *ndev;
	struct mpfs_can_priv *priv;
	struct resource *res;
	int ret;

	ndev = alloc_candev(sizeof(struct mpfs_can_priv), MPFS_CAN_TX_BUFFERS);
	if (!ndev)
		return -ENOMEM;

	priv = netdev_priv(ndev);
	priv->dev = &pdev->dev;
	priv->can.bittiming_const = &mpfs_can_bittiming_const;
	priv->can.do_set_mode = mpfs_can_do_set_mode;
	priv->can.do_get_berr_counter = mpfs_can_get_berr_counter;
	priv->can.ctrlmode_supported = CAN_CTRLMODE_LOOPBACK | CAN_CTRLMODE_BERR_REPORTING;
	priv->tx_max = MPFS_CAN_TX_BUFFERS;

	priv->base = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(priv->base)) {
		ret = PTR_ERR(priv->base);
		goto err_free_candev;
	}

	spin_lock_init(&priv->tx_lock);

	ndev->irq = platform_get_irq(pdev, 0);
	ndev->flags |= IFF_ECHO;
	ndev->netdev_ops = &mpfs_can_netdev_ops;
	platform_set_drvdata(pdev, ndev);
	SET_NETDEV_DEV(ndev, &pdev->dev);

	ret = clk_bulk_get_all(&pdev->dev, &priv->clks);
	if (ret < 2)
		goto err_free_candev;

	priv->num_clocks = ret;
	ret = clk_bulk_prepare_enable(priv->num_clocks, priv->clks);
	if (ret)
		goto err_free_candev;

	/* Retrieve the CAN clock rate */
	priv->can.clock.freq = clk_get_rate(priv->clks[1].clk);

	netif_napi_add_weight(ndev, &priv->napi, mpfs_can_rx_poll, MPFS_CAN_RX_BUFFERS);

	ret = register_candev(ndev);
	if (ret) {
		dev_err(&pdev->dev, "failed to register can device\n");
		goto err_del_napi;
	}

	netdev_dbg(ndev, "reg=0x%p irq=%d clock=%d, max tx buffers %d\n",
		   priv->base, ndev->irq, priv->can.clock.freq,
		   priv->tx_max);

	return 0;

err_del_napi:
	netif_napi_del(&priv->napi);
err_free_candev:
	free_candev(ndev);

	return ret;
}

static void mpfs_can_remove(struct platform_device *pdev)
{
	struct net_device *ndev = platform_get_drvdata(pdev);
	struct mpfs_can_priv *priv = netdev_priv(ndev);

	unregister_candev(ndev);
	netif_napi_del(&priv->napi);
	free_candev(ndev);
}

static const struct of_device_id mpfs_can_of_match[] = {
	{ .compatible = "microchip,mpfs-can", .data = NULL },
	{ },
};

MODULE_DEVICE_TABLE(of, mpfs_can_of_match);

static struct platform_driver mpfs_can_driver = {
	.probe = mpfs_can_probe,
	.remove	= mpfs_can_remove,
	.driver	= {
		.name = "mpfs_can",
		.of_match_table	= mpfs_can_of_match,
	},
};

module_platform_driver(mpfs_can_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microchip Polarfire SoC MSS CAN controller driver");
MODULE_AUTHOR("Naga Sureshkumar Relli <nagasuresh.relli@microchip.com");
