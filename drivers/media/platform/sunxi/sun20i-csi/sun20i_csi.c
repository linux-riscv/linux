// SPDX-License-Identifier: GPL-2.0-only
/*
 * Allwinner D1/T113 CMOS Sensor Interface Controller (CSIC) driver
 *
 * Copyright (C) 2026 Nguyen Minh Tien <tien.nguyenminh@embeddedlinux.blog>
 *
 * The CSIC is split into a parser, which receives the parallel bus, and a
 * DMA engine, which writes frames to memory and can convert YUV 4:2:2 input
 * to semi-planar, planar or luma-only output. The parser is exposed as a
 * bridge subdev and the DMA engine as the capture video device.
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include <media/media-device.h>
#include <media/v4l2-async.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-mc.h>
#include <media/v4l2-subdev.h>
#include <media/videobuf2-dma-contig.h>

/* Register and field names as in the T113-S3 user manual v1.3, section 6.1. */
#define SUN20I_CSI_TOP_EN_REG			0x0800
#define SUN20I_CSI_TOP_EN_CSIC_TOP_EN		BIT(0)

#define SUN20I_CSI_PRS_EN_REG			0x1000
#define SUN20I_CSI_PRS_EN_NCSIC_EN		BIT(16)
#define SUN20I_CSI_PRS_EN_PCLK_EN		BIT(15)
#define SUN20I_CSI_PRS_EN_PRS_EN		BIT(0)

/*
 * The parser takes HREF and VREF, which are the inverse of HSYNC and VSYNC,
 * so an active low sync signal needs the positive (set) HREF_POL or VREF_POL,
 * as explained for the A10 CSI in commit 1948dcf0f928 ("media: sun4i-csi:
 * Fix [HV]sync polarity handling"). With CLK_POL set, the data changes on the
 * falling edge of the pixel clock and is sampled on the rising edge.
 */
#define SUN20I_CSI_PRS_NCSIC_IF_CFG_REG		0x1004
#define SUN20I_CSI_PRS_NCSIC_IF_CFG_VREF_POL	BIT(18)
#define SUN20I_CSI_PRS_NCSIC_IF_CFG_HREF_POL	BIT(17)
#define SUN20I_CSI_PRS_NCSIC_IF_CFG_CLK_POL	BIT(16)
#define SUN20I_CSI_PRS_NCSIC_IF_CFG_INPUT_SEQ	GENMASK(7, 6)
#define SUN20I_CSI_INPUT_SEQ_YUYV		0
#define SUN20I_CSI_INPUT_SEQ_UYVY		2

#define SUN20I_CSI_PRS_CAP_REG			0x100c
#define SUN20I_CSI_PRS_CAP_CH0_VCAP_ON		BIT(1)

#define SUN20I_CSI_PRS_CH0_INFMT_REG		0x1024
#define SUN20I_CSI_INPUT_FMT_RAW		0
#define SUN20I_CSI_INPUT_FMT_YUV422		3
#define SUN20I_CSI_PRS_CH0_OUTPUT_HSIZE_REG	0x1028
#define SUN20I_CSI_PRS_CH0_OUTPUT_VSIZE_REG	0x102c

/* HOR_LEN and VER_LEN of the parser and DMA size registers, from bit 16. */
#define SUN20I_CSI_LEN				GENMASK(28, 16)

#define SUN20I_CSI_DMA_EN_REG			0x9000
/* VFLIP_BUF_ADDR, BUF_LENGTH and FLIP_SIZE set by software, as on reset. */
#define SUN20I_CSI_DMA_EN_SW_CFG_MODE		GENMASK(30, 28)
#define SUN20I_CSI_DMA_EN_DMA_EN		BIT(4)
#define SUN20I_CSI_DMA_EN_BK_TOP_EN		BIT(0)
#define SUN20I_CSI_DMA_CFG_REG			0x9004
#define SUN20I_CSI_DMA_CFG_OUTPUT_FMT		GENMASK(19, 16)
#define SUN20I_CSI_DMA_HSIZE_REG		0x9010
#define SUN20I_CSI_DMA_VSIZE_REG		0x9014
/* The buffer addresses are in 32-bit words, which the manual doesn't say. */
#define SUN20I_CSI_DMA_F0_BUFA_REG		0x9020
#define SUN20I_CSI_DMA_F1_BUFA_REG		0x9028
#define SUN20I_CSI_DMA_F2_BUFA_REG		0x9030
#define SUN20I_CSI_DMA_BUF_LEN_REG		0x9038
#define SUN20I_CSI_DMA_BUF_LEN_BUF_LEN_C	GENMASK(29, 16)
#define SUN20I_CSI_DMA_BUF_LEN_BUF_LEN		GENMASK(13, 0)
#define SUN20I_CSI_DMA_INT_EN_REG		0x9050
#define SUN20I_CSI_DMA_INT_STA_REG		0x9054
#define SUN20I_CSI_DMA_INT_VS			BIT(7)
#define SUN20I_CSI_DMA_INT_HB_OF		BIT(6)
#define SUN20I_CSI_DMA_INT_LC			BIT(5)
#define SUN20I_CSI_DMA_INT_FIFO2_OF		BIT(4)
#define SUN20I_CSI_DMA_INT_FIFO1_OF		BIT(3)
#define SUN20I_CSI_DMA_INT_FIFO0_OF		BIT(2)
#define SUN20I_CSI_DMA_INT_FD			BIT(1)
#define SUN20I_CSI_DMA_INT_OF		(SUN20I_CSI_DMA_INT_HB_OF | \
					 SUN20I_CSI_DMA_INT_FIFO2_OF | \
					 SUN20I_CSI_DMA_INT_FIFO1_OF | \
					 SUN20I_CSI_DMA_INT_FIFO0_OF)
#define SUN20I_CSI_DMA_LINE_CNT_REG		0x9058
#define SUN20I_CSI_DMA_LINE_CNT_LINE_CNT_NUM	GENMASK(12, 0)

/* OUTPUT_FMT values: "frame" modes, for raw or YUV 4:2:2 input. */
#define SUN20I_CSI_OUT_RAW_8			0x8
#define SUN20I_CSI_OUT_PLANAR_420		0x2
#define SUN20I_CSI_OUT_PLANAR_422		0x3
#define SUN20I_CSI_OUT_UV_420			0x6
#define SUN20I_CSI_OUT_UV_422			0x7
#define SUN20I_CSI_OUT_VU_420			0xa
#define SUN20I_CSI_OUT_VU_422			0xb
#define SUN20I_CSI_OUT_Y400			0xf

/* Rate of the module clock, csi_top_clk. */
#define SUN20I_CSI_MOD_RATE			300000000
#define SUN20I_CSI_MIN_SIZE			32
/* HOR_LEN is 13 bits and counts bytes for raw input, 2 bytes per pixel. */
#define SUN20I_CSI_MAX_WIDTH			4088
#define SUN20I_CSI_MAX_HEIGHT			4096

enum {
	SUN20I_CSI_PAD_SINK,
	SUN20I_CSI_PAD_SOURCE,
	SUN20I_CSI_NUM_PADS,
};

struct sun20i_csi_format {
	u32 fourcc;
	/* The only bus code, or 0 for any YUV 4:2:2 code (converted). */
	u32 code;
	u8 output;
	u8 bpp;		/* Bytes per pixel in the first plane */
	u8 planes;	/* 1: packed or luma, 2: semi-planar, 3: planar */
	u8 vsub;	/* Vertical chroma subsampling */
	bool swap_uv;	/* Planar: V before U */
	bool raw;	/* Stored as received, no conversion */
	bool bayer;
};

static const u32 sun20i_csi_yuv_codes[] = {
	MEDIA_BUS_FMT_YUYV8_2X8,
	MEDIA_BUS_FMT_UYVY8_2X8,
};

static const u32 sun20i_csi_raw_codes[] = {
	MEDIA_BUS_FMT_RGB565_2X8_LE,
	MEDIA_BUS_FMT_RGB565_2X8_BE,
	MEDIA_BUS_FMT_SBGGR8_1X8,
	MEDIA_BUS_FMT_SGBRG8_1X8,
	MEDIA_BUS_FMT_SGRBG8_1X8,
	MEDIA_BUS_FMT_SRGGB8_1X8,
};

#define SUN20I_CSI_YUV(_fourcc, _output, _planes, _vsub, _swap_uv)	\
	{ .fourcc = _fourcc, .output = _output, .bpp = 1,		\
	  .planes = _planes, .vsub = _vsub, .swap_uv = _swap_uv }
#define SUN20I_CSI_RAW(_fourcc, _code, _bpp, _bayer)			\
	{ .fourcc = _fourcc, .code = _code, .output = SUN20I_CSI_OUT_RAW_8, \
	  .bpp = _bpp, .planes = 1, .vsub = 1, .raw = true, .bayer = _bayer }

static const struct sun20i_csi_format sun20i_csi_formats[] = {
	SUN20I_CSI_YUV(V4L2_PIX_FMT_NV12, SUN20I_CSI_OUT_UV_420, 2, 2, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_NV21, SUN20I_CSI_OUT_VU_420, 2, 2, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_NV16, SUN20I_CSI_OUT_UV_422, 2, 1, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_NV61, SUN20I_CSI_OUT_VU_422, 2, 1, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_YUV420, SUN20I_CSI_OUT_PLANAR_420,
		       3, 2, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_YVU420, SUN20I_CSI_OUT_PLANAR_420,
		       3, 2, true),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_YUV422P, SUN20I_CSI_OUT_PLANAR_422,
		       3, 1, false),
	SUN20I_CSI_YUV(V4L2_PIX_FMT_GREY, SUN20I_CSI_OUT_Y400, 1, 1, false),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_YUYV, MEDIA_BUS_FMT_YUYV8_2X8, 2, false),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_UYVY, MEDIA_BUS_FMT_UYVY8_2X8, 2, false),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_RGB565, MEDIA_BUS_FMT_RGB565_2X8_LE,
		       2, false),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_RGB565X, MEDIA_BUS_FMT_RGB565_2X8_BE,
		       2, false),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_SBGGR8, MEDIA_BUS_FMT_SBGGR8_1X8, 1, true),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_SGBRG8, MEDIA_BUS_FMT_SGBRG8_1X8, 1, true),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_SGRBG8, MEDIA_BUS_FMT_SGRBG8_1X8, 1, true),
	SUN20I_CSI_RAW(V4L2_PIX_FMT_SRGGB8, MEDIA_BUS_FMT_SRGGB8_1X8, 1, true),
};

struct sun20i_csi_buffer {
	struct vb2_v4l2_buffer vb;
	struct list_head list;
};

struct sun20i_csi {
	struct device *dev;
	void __iomem *regs;
	struct clk *bus_clk;
	struct clk *mod_clk;
	struct clk *ram_clk;
	struct reset_control *reset;
	int irq;

	struct media_device mdev;
	struct v4l2_device v4l2_dev;
	struct v4l2_async_notifier notifier;
	struct v4l2_mbus_config_parallel bus;

	/* The parser, as a bridge subdev */
	struct v4l2_subdev subdev;
	struct media_pad pads[SUN20I_CSI_NUM_PADS];
	struct v4l2_subdev *source;
	u16 source_pad;

	/* The DMA engine, as the capture video device */
	struct video_device vdev;
	struct media_pad vdev_pad;
	struct vb2_queue queue;
	struct mutex lock;		/* The video device and the queue */
	struct v4l2_pix_format format;
	const struct sun20i_csi_format *fmt;

	spinlock_t irqlock;		/* The fields below */
	struct list_head queued;
	/* The buffer being written, and the one in the address registers */
	struct sun20i_csi_buffer *active;
	struct sun20i_csi_buffer *next;
	bool active_complete;
	bool active_error;
	u32 sequence;
	u32 errors;
};

static inline void sun20i_csi_write(struct sun20i_csi *csi, u32 reg, u32 val)
{
	writel(val, csi->regs + reg);
}

static inline u32 sun20i_csi_read(struct sun20i_csi *csi, u32 reg)
{
	return readl(csi->regs + reg);
}

static bool sun20i_csi_code_supported(u32 code)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sun20i_csi_yuv_codes); i++)
		if (sun20i_csi_yuv_codes[i] == code)
			return true;
	for (i = 0; i < ARRAY_SIZE(sun20i_csi_raw_codes); i++)
		if (sun20i_csi_raw_codes[i] == code)
			return true;
	return false;
}

static bool sun20i_csi_format_takes(const struct sun20i_csi_format *fmt,
				    u32 code)
{
	unsigned int i;

	if (fmt->code)
		return fmt->code == code;

	for (i = 0; i < ARRAY_SIZE(sun20i_csi_yuv_codes); i++)
		if (sun20i_csi_yuv_codes[i] == code)
			return true;
	return false;
}

static const struct sun20i_csi_format *sun20i_csi_find_format(u32 fourcc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sun20i_csi_formats); i++)
		if (sun20i_csi_formats[i].fourcc == fourcc)
			return &sun20i_csi_formats[i];
	return NULL;
}

/* Number of units in a line for the parser and the DMA engine. */
static u32 sun20i_csi_line_units(const struct sun20i_csi_format *fmt, u32 width)
{
	/* Raw input is counted in bytes, YUV input in pixels. */
	return fmt->raw ? width * fmt->bpp : width;
}

/* -------------------------------------------------------------------------
 * Buffers and interrupt
 */

static void sun20i_csi_set_buffer(struct sun20i_csi *csi,
				  struct sun20i_csi_buffer *buf)
{
	dma_addr_t addr = vb2_dma_contig_plane_dma_addr(&buf->vb.vb2_buf, 0);
	u32 width = csi->format.width, height = csi->format.height;
	const struct sun20i_csi_format *fmt = csi->fmt;
	dma_addr_t cb, cr;

	sun20i_csi_write(csi, SUN20I_CSI_DMA_F0_BUFA_REG, addr >> 2);
	if (fmt->planes == 1)
		return;

	cb = addr + width * height;
	if (fmt->planes == 3) {
		cr = cb + width / 2 * (height / fmt->vsub);
		if (fmt->swap_uv)
			swap(cb, cr);
		sun20i_csi_write(csi, SUN20I_CSI_DMA_F2_BUFA_REG, cr >> 2);
	}
	sun20i_csi_write(csi, SUN20I_CSI_DMA_F1_BUFA_REG, cb >> 2);
}

/*
 * Frame done. It also comes for a frame cut short, such as the first one
 * after the sensor starts, so only a frame whose last line was written (the
 * line counter interrupt) counts.
 */
static void sun20i_csi_frame_done(struct sun20i_csi *csi)
{
	struct sun20i_csi_buffer *buf = csi->active;

	csi->active = NULL;

	/* No buffer was queued: the next frame is going into this one. */
	if (buf == csi->next)
		buf = NULL;

	if (!csi->active_complete) {
		if (buf)
			list_add(&buf->list, &csi->queued);
		return;
	}

	if (buf) {
		buf->vb.vb2_buf.timestamp = ktime_get_ns();
		buf->vb.sequence = csi->sequence;
		buf->vb.field = V4L2_FIELD_NONE;
		vb2_buffer_done(&buf->vb.vb2_buf, csi->active_error ?
				VB2_BUF_STATE_ERROR : VB2_BUF_STATE_DONE);
	}
	csi->sequence++;
}

/*
 * Frame start. The manual: "at this time load the buffer address for the
 * coming frame. So after this irq come, changing the buffer address could
 * only effect next frame". The address registers take the next buffer here.
 */
static void sun20i_csi_frame_start(struct sun20i_csi *csi)
{
	/* A frame that started but was never done: reuse its buffer. */
	if (csi->active && csi->active != csi->next)
		list_add(&csi->active->list, &csi->queued);

	csi->active = csi->next;
	csi->active_complete = false;
	csi->active_error = false;

	csi->next = list_first_entry_or_null(&csi->queued,
					     struct sun20i_csi_buffer, list);
	if (csi->next) {
		list_del(&csi->next->list);
		sun20i_csi_set_buffer(csi, csi->next);
	} else {
		/* Nothing queued: the next frame goes into the same buffer. */
		csi->next = csi->active;
	}
}

static irqreturn_t sun20i_csi_irq(int irq, void *data)
{
	struct sun20i_csi *csi = data;
	u32 status;

	status = sun20i_csi_read(csi, SUN20I_CSI_DMA_INT_STA_REG);
	sun20i_csi_write(csi, SUN20I_CSI_DMA_INT_STA_REG, status);
	status &= SUN20I_CSI_DMA_INT_VS | SUN20I_CSI_DMA_INT_LC |
		  SUN20I_CSI_DMA_INT_FD | SUN20I_CSI_DMA_INT_OF;
	if (!status)
		return IRQ_NONE;

	spin_lock(&csi->irqlock);

	/* The line counter is set to the last line of the frame. */
	if (status & SUN20I_CSI_DMA_INT_LC)
		csi->active_complete = true;

	if (status & SUN20I_CSI_DMA_INT_OF) {
		csi->active_error = true;
		csi->errors++;
	}

	/* A frame ends before the next one starts. */
	if (status & SUN20I_CSI_DMA_INT_FD)
		sun20i_csi_frame_done(csi);
	if (status & SUN20I_CSI_DMA_INT_VS)
		sun20i_csi_frame_start(csi);

	spin_unlock(&csi->irqlock);

	return IRQ_HANDLED;
}

/* -------------------------------------------------------------------------
 * Bridge subdev (the parser)
 */

static const struct v4l2_mbus_framefmt sun20i_csi_default_fmt = {
	.width = 640,
	.height = 480,
	.code = MEDIA_BUS_FMT_YUYV8_2X8,
	.field = V4L2_FIELD_NONE,
	.colorspace = V4L2_COLORSPACE_SRGB,
	.ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT,
	.quantization = V4L2_QUANTIZATION_DEFAULT,
	.xfer_func = V4L2_XFER_FUNC_DEFAULT,
};

static struct sun20i_csi *sd_to_csi(struct v4l2_subdev *sd)
{
	return container_of(sd, struct sun20i_csi, subdev);
}

static int sun20i_csi_bridge_init_state(struct v4l2_subdev *sd,
					struct v4l2_subdev_state *state)
{
	*v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SINK) =
		sun20i_csi_default_fmt;
	*v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SOURCE) =
		sun20i_csi_default_fmt;

	return 0;
}

static int
sun20i_csi_bridge_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	unsigned int nyuv = ARRAY_SIZE(sun20i_csi_yuv_codes);

	/* The source pad passes on the sink pad format. */
	if (code->pad == SUN20I_CSI_PAD_SOURCE) {
		const struct v4l2_mbus_framefmt *fmt;

		if (code->index)
			return -EINVAL;
		fmt = v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SINK);
		code->code = fmt->code;
		return 0;
	}

	if (code->index < nyuv)
		code->code = sun20i_csi_yuv_codes[code->index];
	else if (code->index - nyuv < ARRAY_SIZE(sun20i_csi_raw_codes))
		code->code = sun20i_csi_raw_codes[code->index - nyuv];
	else
		return -EINVAL;

	return 0;
}

static int
sun20i_csi_bridge_enum_frame_size(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state,
				  struct v4l2_subdev_frame_size_enum *fse)
{
	if (fse->index)
		return -EINVAL;

	if (fse->pad == SUN20I_CSI_PAD_SOURCE) {
		const struct v4l2_mbus_framefmt *fmt;

		fmt = v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SINK);
		if (fse->code != fmt->code)
			return -EINVAL;
		fse->min_width = fmt->width;
		fse->max_width = fmt->width;
		fse->min_height = fmt->height;
		fse->max_height = fmt->height;
		return 0;
	}

	if (!sun20i_csi_code_supported(fse->code))
		return -EINVAL;

	fse->min_width = SUN20I_CSI_MIN_SIZE;
	fse->max_width = SUN20I_CSI_MAX_WIDTH;
	fse->min_height = SUN20I_CSI_MIN_SIZE;
	fse->max_height = SUN20I_CSI_MAX_HEIGHT;

	return 0;
}

static int sun20i_csi_bridge_set_fmt(struct v4l2_subdev *sd,
				     const struct v4l2_subdev_client_info *ci,
				     struct v4l2_subdev_state *state,
				     struct v4l2_subdev_format *format)
{
	struct v4l2_mbus_framefmt *fmt = &format->format;

	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE &&
	    v4l2_subdev_is_streaming(sd))
		return -EBUSY;

	/* The source pad format follows the sink pad format. */
	if (format->pad == SUN20I_CSI_PAD_SOURCE)
		return v4l2_subdev_get_fmt(sd, state, format);

	if (!sun20i_csi_code_supported(fmt->code))
		fmt->code = sun20i_csi_default_fmt.code;
	fmt->width = clamp_t(u32, ALIGN(fmt->width, 8), SUN20I_CSI_MIN_SIZE,
			     SUN20I_CSI_MAX_WIDTH);
	fmt->height = clamp_t(u32, ALIGN(fmt->height, 2), SUN20I_CSI_MIN_SIZE,
			      SUN20I_CSI_MAX_HEIGHT);
	fmt->field = V4L2_FIELD_NONE;
	if (fmt->colorspace == V4L2_COLORSPACE_DEFAULT ||
	    fmt->colorspace > V4L2_COLORSPACE_DCI_P3)
		fmt->colorspace = V4L2_COLORSPACE_SRGB;
	if (fmt->ycbcr_enc > V4L2_YCBCR_ENC_SMPTE240M)
		fmt->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	if (fmt->quantization > V4L2_QUANTIZATION_LIM_RANGE)
		fmt->quantization = V4L2_QUANTIZATION_DEFAULT;
	if (fmt->xfer_func > V4L2_XFER_FUNC_SMPTE2084)
		fmt->xfer_func = V4L2_XFER_FUNC_DEFAULT;

	*v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SINK) = *fmt;
	*v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SOURCE) = *fmt;

	return 0;
}

static int sun20i_csi_bridge_enable_streams(struct v4l2_subdev *sd,
					    struct v4l2_subdev_state *state,
					    u32 pad, u64 streams_mask)
{
	const struct v4l2_mbus_framefmt *fmt =
		v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SINK);
	struct sun20i_csi *csi = sd_to_csi(sd);
	u32 cfg = 0, seq, infmt, width;
	int ret;

	if (csi->bus.flags & V4L2_MBUS_VSYNC_ACTIVE_LOW)
		cfg |= SUN20I_CSI_PRS_NCSIC_IF_CFG_VREF_POL;
	if (csi->bus.flags & V4L2_MBUS_HSYNC_ACTIVE_LOW)
		cfg |= SUN20I_CSI_PRS_NCSIC_IF_CFG_HREF_POL;
	if (csi->bus.flags & V4L2_MBUS_PCLK_SAMPLE_RISING)
		cfg |= SUN20I_CSI_PRS_NCSIC_IF_CFG_CLK_POL;
	if (fmt->code == MEDIA_BUS_FMT_UYVY8_2X8)
		seq = SUN20I_CSI_INPUT_SEQ_UYVY;
	else
		seq = SUN20I_CSI_INPUT_SEQ_YUYV;
	cfg |= FIELD_PREP(SUN20I_CSI_PRS_NCSIC_IF_CFG_INPUT_SEQ, seq);

	/* The capture format is fixed while streaming. */
	infmt = csi->fmt->raw ? SUN20I_CSI_INPUT_FMT_RAW :
				SUN20I_CSI_INPUT_FMT_YUV422;
	width = sun20i_csi_line_units(csi->fmt, fmt->width);

	sun20i_csi_write(csi, SUN20I_CSI_PRS_EN_REG,
			 SUN20I_CSI_PRS_EN_NCSIC_EN |
			 SUN20I_CSI_PRS_EN_PCLK_EN | SUN20I_CSI_PRS_EN_PRS_EN);
	sun20i_csi_write(csi, SUN20I_CSI_PRS_NCSIC_IF_CFG_REG, cfg);
	sun20i_csi_write(csi, SUN20I_CSI_PRS_CH0_INFMT_REG, infmt);
	sun20i_csi_write(csi, SUN20I_CSI_PRS_CH0_OUTPUT_HSIZE_REG,
			 FIELD_PREP(SUN20I_CSI_LEN, width));
	sun20i_csi_write(csi, SUN20I_CSI_PRS_CH0_OUTPUT_VSIZE_REG,
			 FIELD_PREP(SUN20I_CSI_LEN, fmt->height));
	sun20i_csi_write(csi, SUN20I_CSI_PRS_CAP_REG,
			 SUN20I_CSI_PRS_CAP_CH0_VCAP_ON);

	ret = v4l2_subdev_enable_streams(csi->source, csi->source_pad,
					 BIT_ULL(0));
	if (ret) {
		sun20i_csi_write(csi, SUN20I_CSI_PRS_CAP_REG, 0);
		sun20i_csi_write(csi, SUN20I_CSI_PRS_EN_REG, 0);
	}

	return ret;
}

static int sun20i_csi_bridge_disable_streams(struct v4l2_subdev *sd,
					     struct v4l2_subdev_state *state,
					     u32 pad, u64 streams_mask)
{
	struct sun20i_csi *csi = sd_to_csi(sd);
	int ret;

	ret = v4l2_subdev_disable_streams(csi->source, csi->source_pad,
					  BIT_ULL(0));

	sun20i_csi_write(csi, SUN20I_CSI_PRS_CAP_REG, 0);
	sun20i_csi_write(csi, SUN20I_CSI_PRS_EN_REG, 0);

	return ret;
}

static const struct v4l2_subdev_pad_ops sun20i_csi_bridge_pad_ops = {
	.enum_mbus_code		= sun20i_csi_bridge_enum_mbus_code,
	.enum_frame_size	= sun20i_csi_bridge_enum_frame_size,
	.get_fmt		= v4l2_subdev_get_fmt,
	.set_fmt		= sun20i_csi_bridge_set_fmt,
	.enable_streams		= sun20i_csi_bridge_enable_streams,
	.disable_streams	= sun20i_csi_bridge_disable_streams,
};

static const struct v4l2_subdev_ops sun20i_csi_bridge_ops = {
	.pad			= &sun20i_csi_bridge_pad_ops,
};

static const struct v4l2_subdev_internal_ops sun20i_csi_bridge_internal_ops = {
	.init_state		= sun20i_csi_bridge_init_state,
};

static const struct media_entity_operations sun20i_csi_bridge_entity_ops = {
	.link_validate		= v4l2_subdev_link_validate,
};

/* -------------------------------------------------------------------------
 * Capture video device (the DMA engine)
 */

static void sun20i_csi_fill_format(struct v4l2_pix_format *pix)
{
	const struct sun20i_csi_format *fmt;
	u32 size, width, height;

	fmt = sun20i_csi_find_format(pix->pixelformat);
	if (!fmt)
		fmt = &sun20i_csi_formats[0];

	width = clamp_t(u32, ALIGN(pix->width, 8), SUN20I_CSI_MIN_SIZE,
			SUN20I_CSI_MAX_WIDTH);
	height = clamp_t(u32, ALIGN(pix->height, 2), SUN20I_CSI_MIN_SIZE,
			 SUN20I_CSI_MAX_HEIGHT);

	pix->pixelformat = fmt->fourcc;
	pix->width = width;
	pix->height = height;
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = width * fmt->bpp;

	size = pix->bytesperline * height;
	/* Semi-planar: full-width UV lines. Planar: two half-width planes. */
	if (fmt->planes > 1)
		size += width * (height / fmt->vsub);
	pix->sizeimage = size;

	pix->colorspace = fmt->bayer ? V4L2_COLORSPACE_RAW :
				       V4L2_COLORSPACE_SRGB;
	pix->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	pix->quantization = V4L2_QUANTIZATION_DEFAULT;
	pix->xfer_func = V4L2_XFER_FUNC_DEFAULT;
	pix->flags = 0;
}

static int sun20i_csi_querycap(struct file *file, void *priv,
			       struct v4l2_capability *cap)
{
	strscpy(cap->driver, "sun20i-csi", sizeof(cap->driver));
	strscpy(cap->card, "Allwinner D1 CSIC", sizeof(cap->card));

	return 0;
}

static int sun20i_csi_enum_fmt(struct file *file, void *priv,
			       struct v4l2_fmtdesc *f)
{
	unsigned int i, index = 0;

	for (i = 0; i < ARRAY_SIZE(sun20i_csi_formats); i++) {
		const struct sun20i_csi_format *fmt = &sun20i_csi_formats[i];

		if (f->mbus_code && !sun20i_csi_format_takes(fmt, f->mbus_code))
			continue;
		if (index++ == f->index) {
			f->pixelformat = fmt->fourcc;
			return 0;
		}
	}

	return -EINVAL;
}

static int sun20i_csi_enum_framesizes(struct file *file, void *priv,
				      struct v4l2_frmsizeenum *fsize)
{
	if (fsize->index || !sun20i_csi_find_format(fsize->pixel_format))
		return -EINVAL;

	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise.min_width = SUN20I_CSI_MIN_SIZE;
	fsize->stepwise.max_width = SUN20I_CSI_MAX_WIDTH;
	fsize->stepwise.step_width = 8;
	fsize->stepwise.min_height = SUN20I_CSI_MIN_SIZE;
	fsize->stepwise.max_height = SUN20I_CSI_MAX_HEIGHT;
	fsize->stepwise.step_height = 2;

	return 0;
}

static int sun20i_csi_g_fmt(struct file *file, void *priv,
			    struct v4l2_format *f)
{
	struct sun20i_csi *csi = video_drvdata(file);

	f->fmt.pix = csi->format;

	return 0;
}

static int sun20i_csi_try_fmt(struct file *file, void *priv,
			      struct v4l2_format *f)
{
	sun20i_csi_fill_format(&f->fmt.pix);

	return 0;
}

static int sun20i_csi_s_fmt(struct file *file, void *priv,
			    struct v4l2_format *f)
{
	struct sun20i_csi *csi = video_drvdata(file);

	if (vb2_is_busy(&csi->queue))
		return -EBUSY;

	sun20i_csi_fill_format(&f->fmt.pix);
	csi->format = f->fmt.pix;
	csi->fmt = sun20i_csi_find_format(f->fmt.pix.pixelformat);

	return 0;
}

static const struct v4l2_ioctl_ops sun20i_csi_ioctl_ops = {
	.vidioc_querycap		= sun20i_csi_querycap,
	.vidioc_enum_fmt_vid_cap	= sun20i_csi_enum_fmt,
	.vidioc_enum_framesizes		= sun20i_csi_enum_framesizes,
	.vidioc_g_fmt_vid_cap		= sun20i_csi_g_fmt,
	.vidioc_try_fmt_vid_cap		= sun20i_csi_try_fmt,
	.vidioc_s_fmt_vid_cap		= sun20i_csi_s_fmt,

	.vidioc_reqbufs			= vb2_ioctl_reqbufs,
	.vidioc_create_bufs		= vb2_ioctl_create_bufs,
	.vidioc_prepare_buf		= vb2_ioctl_prepare_buf,
	.vidioc_querybuf		= vb2_ioctl_querybuf,
	.vidioc_qbuf			= vb2_ioctl_qbuf,
	.vidioc_dqbuf			= vb2_ioctl_dqbuf,
	.vidioc_expbuf			= vb2_ioctl_expbuf,
	.vidioc_streamon		= vb2_ioctl_streamon,
	.vidioc_streamoff		= vb2_ioctl_streamoff,
};

static const struct v4l2_file_operations sun20i_csi_fops = {
	.owner		= THIS_MODULE,
	.open		= v4l2_fh_open,
	.release	= vb2_fop_release,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= vb2_fop_mmap,
	.poll		= vb2_fop_poll,
};

static int sun20i_csi_queue_setup(struct vb2_queue *queue,
				  unsigned int *num_buffers,
				  unsigned int *num_planes,
				  unsigned int sizes[],
				  struct device *alloc_devs[])
{
	struct sun20i_csi *csi = vb2_get_drv_priv(queue);

	if (*num_planes)
		return sizes[0] < csi->format.sizeimage ? -EINVAL : 0;

	*num_planes = 1;
	sizes[0] = csi->format.sizeimage;

	return 0;
}

static int sun20i_csi_buf_prepare(struct vb2_buffer *vb)
{
	struct sun20i_csi *csi = vb2_get_drv_priv(vb->vb2_queue);

	if (vb2_plane_size(vb, 0) < csi->format.sizeimage)
		return -EINVAL;

	vb2_set_plane_payload(vb, 0, csi->format.sizeimage);

	return 0;
}

static void sun20i_csi_buf_queue(struct vb2_buffer *vb)
{
	struct sun20i_csi *csi = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct sun20i_csi_buffer *buf =
		container_of(vbuf, struct sun20i_csi_buffer, vb);
	unsigned long flags;

	spin_lock_irqsave(&csi->irqlock, flags);
	list_add_tail(&buf->list, &csi->queued);
	spin_unlock_irqrestore(&csi->irqlock, flags);
}

static void sun20i_csi_return_buffers(struct sun20i_csi *csi,
				      enum vb2_buffer_state state)
{
	struct sun20i_csi_buffer *buf, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&csi->irqlock, flags);

	if (csi->active)
		vb2_buffer_done(&csi->active->vb.vb2_buf, state);
	if (csi->next && csi->next != csi->active)
		vb2_buffer_done(&csi->next->vb.vb2_buf, state);
	csi->active = NULL;
	csi->next = NULL;

	list_for_each_entry_safe(buf, tmp, &csi->queued, list) {
		list_del(&buf->list);
		vb2_buffer_done(&buf->vb.vb2_buf, state);
	}

	spin_unlock_irqrestore(&csi->irqlock, flags);
}

static void sun20i_csi_dma_start(struct sun20i_csi *csi)
{
	const struct sun20i_csi_format *fmt = csi->fmt;
	u32 width = csi->format.width, height = csi->format.height;
	u32 line_c = fmt->planes == 3 ? width / 2 : width;
	unsigned long flags;

	/*
	 * This relies on two reset values: the CSIC's own clock gates are
	 * bypassed (CCU_CLK_MODE_REG), and DMA0 takes input 0, "ISP0 CH0",
	 * which carries the parser's channel 0 (CSIC_DMA0_INPUT_SEL_REG).
	 */
	sun20i_csi_write(csi, SUN20I_CSI_TOP_EN_REG,
			 SUN20I_CSI_TOP_EN_CSIC_TOP_EN);

	sun20i_csi_write(csi, SUN20I_CSI_DMA_CFG_REG,
			 FIELD_PREP(SUN20I_CSI_DMA_CFG_OUTPUT_FMT,
				    fmt->output));
	sun20i_csi_write(csi, SUN20I_CSI_DMA_HSIZE_REG,
			 FIELD_PREP(SUN20I_CSI_LEN,
				    sun20i_csi_line_units(fmt, width)));
	sun20i_csi_write(csi, SUN20I_CSI_DMA_VSIZE_REG,
			 FIELD_PREP(SUN20I_CSI_LEN, height));
	sun20i_csi_write(csi, SUN20I_CSI_DMA_BUF_LEN_REG,
			 FIELD_PREP(SUN20I_CSI_DMA_BUF_LEN_BUF_LEN_C, line_c) |
			 FIELD_PREP(SUN20I_CSI_DMA_BUF_LEN_BUF_LEN,
				    csi->format.bytesperline));

	spin_lock_irqsave(&csi->irqlock, flags);

	csi->sequence = 0;
	csi->errors = 0;
	csi->active = NULL;
	/* vb2 makes sure that min_queued_buffers are queued. */
	csi->next = list_first_entry(&csi->queued, struct sun20i_csi_buffer,
				     list);
	list_del(&csi->next->list);
	sun20i_csi_set_buffer(csi, csi->next);

	spin_unlock_irqrestore(&csi->irqlock, flags);

	/* The line index counts from 0: this fires on the last line. */
	sun20i_csi_write(csi, SUN20I_CSI_DMA_LINE_CNT_REG,
			 FIELD_PREP(SUN20I_CSI_DMA_LINE_CNT_LINE_CNT_NUM,
				    height - 1));
	sun20i_csi_write(csi, SUN20I_CSI_DMA_INT_STA_REG, ~0);
	sun20i_csi_write(csi, SUN20I_CSI_DMA_INT_EN_REG,
			 SUN20I_CSI_DMA_INT_VS | SUN20I_CSI_DMA_INT_LC |
			 SUN20I_CSI_DMA_INT_FD | SUN20I_CSI_DMA_INT_OF);
	sun20i_csi_write(csi, SUN20I_CSI_DMA_EN_REG,
			 SUN20I_CSI_DMA_EN_SW_CFG_MODE |
			 SUN20I_CSI_DMA_EN_DMA_EN |
			 SUN20I_CSI_DMA_EN_BK_TOP_EN);
}

static void sun20i_csi_dma_stop(struct sun20i_csi *csi)
{
	sun20i_csi_write(csi, SUN20I_CSI_DMA_INT_EN_REG, 0);
	sun20i_csi_write(csi, SUN20I_CSI_DMA_EN_REG,
			 SUN20I_CSI_DMA_EN_SW_CFG_MODE);
	sun20i_csi_write(csi, SUN20I_CSI_DMA_INT_STA_REG, ~0);
	sun20i_csi_write(csi, SUN20I_CSI_TOP_EN_REG, 0);
	synchronize_irq(csi->irq);
}

static int sun20i_csi_start_streaming(struct vb2_queue *queue,
				      unsigned int count)
{
	struct sun20i_csi *csi = vb2_get_drv_priv(queue);
	int ret;

	ret = pm_runtime_resume_and_get(csi->dev);
	if (ret)
		goto err_return_buffers;

	ret = video_device_pipeline_alloc_start(&csi->vdev);
	if (ret)
		goto err_pm_put;

	sun20i_csi_dma_start(csi);

	ret = v4l2_subdev_enable_streams(&csi->subdev, SUN20I_CSI_PAD_SOURCE,
					 BIT_ULL(0));
	if (ret)
		goto err_dma_stop;

	return 0;

err_dma_stop:
	sun20i_csi_dma_stop(csi);
	video_device_pipeline_stop(&csi->vdev);
err_pm_put:
	pm_runtime_put(csi->dev);
err_return_buffers:
	sun20i_csi_return_buffers(csi, VB2_BUF_STATE_QUEUED);
	return ret;
}

static void sun20i_csi_stop_streaming(struct vb2_queue *queue)
{
	struct sun20i_csi *csi = vb2_get_drv_priv(queue);

	v4l2_subdev_disable_streams(&csi->subdev, SUN20I_CSI_PAD_SOURCE,
				    BIT_ULL(0));
	sun20i_csi_dma_stop(csi);
	video_device_pipeline_stop(&csi->vdev);
	sun20i_csi_return_buffers(csi, VB2_BUF_STATE_ERROR);
	pm_runtime_put(csi->dev);

	if (csi->errors)
		dev_dbg(csi->dev, "%u FIFO overflows in %u frames\n",
			csi->errors, csi->sequence);
}

static const struct vb2_ops sun20i_csi_vb2_ops = {
	.queue_setup		= sun20i_csi_queue_setup,
	.buf_prepare		= sun20i_csi_buf_prepare,
	.buf_queue		= sun20i_csi_buf_queue,
	.start_streaming	= sun20i_csi_start_streaming,
	.stop_streaming		= sun20i_csi_stop_streaming,
};

static int sun20i_csi_capture_link_validate(struct media_link *link)
{
	struct video_device *vdev =
		media_entity_to_video_device(link->sink->entity);
	struct sun20i_csi *csi = video_get_drvdata(vdev);
	const struct v4l2_mbus_framefmt *fmt;
	struct v4l2_subdev_state *state;
	int ret = 0;

	state = v4l2_subdev_lock_and_get_active_state(&csi->subdev);
	fmt = v4l2_subdev_state_get_format(state, SUN20I_CSI_PAD_SOURCE);

	if (fmt->width != csi->format.width ||
	    fmt->height != csi->format.height) {
		dev_dbg(csi->dev, "size mismatch: %ux%u on the bridge, %ux%u on the video device\n",
			fmt->width, fmt->height,
			csi->format.width, csi->format.height);
		ret = -EPIPE;
	} else if (!sun20i_csi_format_takes(csi->fmt, fmt->code)) {
		dev_dbg(csi->dev, "%p4cc can't be captured from bus code 0x%04x\n",
			&csi->format.pixelformat, fmt->code);
		ret = -EPIPE;
	}

	v4l2_subdev_unlock_state(state);

	return ret;
}

static const struct media_entity_operations sun20i_csi_capture_entity_ops = {
	.link_validate		= sun20i_csi_capture_link_validate,
};

/* -------------------------------------------------------------------------
 * Probe
 */

static int sun20i_csi_notify_bound(struct v4l2_async_notifier *notifier,
				   struct v4l2_subdev *sd,
				   struct v4l2_async_connection *asc)
{
	struct sun20i_csi *csi = container_of(notifier, struct sun20i_csi,
					      notifier);
	struct media_pad *pad = &csi->pads[SUN20I_CSI_PAD_SINK];
	int ret;

	ret = v4l2_create_fwnode_links_to_pad(sd, pad, MEDIA_LNK_FL_ENABLED |
					      MEDIA_LNK_FL_IMMUTABLE);
	if (ret)
		return ret;

	pad = media_pad_remote_pad_first(pad);
	if (!pad)
		return -ENOLINK;

	csi->source = sd;
	csi->source_pad = pad->index;

	return 0;
}

static int sun20i_csi_notify_complete(struct v4l2_async_notifier *notifier)
{
	struct sun20i_csi *csi = container_of(notifier, struct sun20i_csi,
					      notifier);
	int ret;

	ret = v4l2_device_register_subdev_nodes(&csi->v4l2_dev);
	if (ret)
		return ret;

	return media_device_register(&csi->mdev);
}

static const struct v4l2_async_notifier_operations sun20i_csi_notify_ops = {
	.bound		= sun20i_csi_notify_bound,
	.complete	= sun20i_csi_notify_complete,
};

static int sun20i_csi_parse_dt(struct sun20i_csi *csi)
{
	struct v4l2_fwnode_endpoint vep = { .bus_type = V4L2_MBUS_PARALLEL };
	struct v4l2_async_connection *asc;
	struct fwnode_handle *ep;
	int ret;

	ep = fwnode_graph_get_endpoint_by_id(dev_fwnode(csi->dev), 0, 0, 0);
	if (!ep)
		return dev_err_probe(csi->dev, -ENODEV, "no input endpoint\n");

	ret = v4l2_fwnode_endpoint_parse(ep, &vep);
	if (ret) {
		dev_err_probe(csi->dev, ret, "invalid input endpoint\n");
		goto out;
	}
	if (vep.bus.parallel.bus_width != 8 || vep.bus.parallel.data_shift) {
		ret = dev_err_probe(csi->dev, -EINVAL,
				    "only an 8-bit bus is supported\n");
		goto out;
	}
	csi->bus = vep.bus.parallel;

	asc = v4l2_async_nf_add_fwnode_remote(&csi->notifier, ep,
					      struct v4l2_async_connection);
	if (IS_ERR(asc))
		ret = PTR_ERR(asc);

out:
	fwnode_handle_put(ep);
	return ret;
}

static int sun20i_csi_register_bridge(struct sun20i_csi *csi)
{
	struct v4l2_subdev *sd = &csi->subdev;
	int ret;

	v4l2_subdev_init(sd, &sun20i_csi_bridge_ops);
	sd->internal_ops = &sun20i_csi_bridge_internal_ops;
	sd->owner = THIS_MODULE;
	sd->dev = csi->dev;
	sd->flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	strscpy(sd->name, "sun20i-csi-bridge", sizeof(sd->name));

	sd->entity.function = MEDIA_ENT_F_VID_IF_BRIDGE;
	sd->entity.ops = &sun20i_csi_bridge_entity_ops;
	csi->pads[SUN20I_CSI_PAD_SINK].flags = MEDIA_PAD_FL_SINK |
					       MEDIA_PAD_FL_MUST_CONNECT;
	csi->pads[SUN20I_CSI_PAD_SOURCE].flags = MEDIA_PAD_FL_SOURCE |
						 MEDIA_PAD_FL_MUST_CONNECT;
	ret = media_entity_pads_init(&sd->entity, SUN20I_CSI_NUM_PADS,
				     csi->pads);
	if (ret)
		return ret;

	ret = v4l2_subdev_init_finalize(sd);
	if (ret)
		goto err_entity;

	ret = v4l2_device_register_subdev(&csi->v4l2_dev, sd);
	if (ret)
		goto err_subdev;

	return 0;

err_subdev:
	v4l2_subdev_cleanup(sd);
err_entity:
	media_entity_cleanup(&sd->entity);
	return ret;
}

static void sun20i_csi_unregister_bridge(struct sun20i_csi *csi)
{
	v4l2_device_unregister_subdev(&csi->subdev);
	v4l2_subdev_cleanup(&csi->subdev);
	media_entity_cleanup(&csi->subdev.entity);
}

static int sun20i_csi_register_capture(struct sun20i_csi *csi)
{
	struct video_device *vdev = &csi->vdev;
	struct vb2_queue *queue = &csi->queue;
	int ret;

	csi->format.pixelformat = sun20i_csi_formats[0].fourcc;
	csi->format.width = sun20i_csi_default_fmt.width;
	csi->format.height = sun20i_csi_default_fmt.height;
	sun20i_csi_fill_format(&csi->format);
	csi->fmt = &sun20i_csi_formats[0];

	queue->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	queue->io_modes = VB2_MMAP | VB2_DMABUF;
	queue->dev = csi->dev;
	queue->drv_priv = csi;
	queue->buf_struct_size = sizeof(struct sun20i_csi_buffer);
	queue->ops = &sun20i_csi_vb2_ops;
	queue->mem_ops = &vb2_dma_contig_memops;
	queue->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	queue->min_queued_buffers = 2;
	queue->lock = &csi->lock;
	ret = vb2_queue_init(queue);
	if (ret)
		return ret;

	csi->vdev_pad.flags = MEDIA_PAD_FL_SINK | MEDIA_PAD_FL_MUST_CONNECT;
	vdev->entity.ops = &sun20i_csi_capture_entity_ops;
	ret = media_entity_pads_init(&vdev->entity, 1, &csi->vdev_pad);
	if (ret)
		return ret;

	strscpy(vdev->name, "sun20i-csi-capture", sizeof(vdev->name));
	vdev->v4l2_dev = &csi->v4l2_dev;
	vdev->fops = &sun20i_csi_fops;
	vdev->ioctl_ops = &sun20i_csi_ioctl_ops;
	vdev->release = video_device_release_empty;
	vdev->lock = &csi->lock;
	vdev->queue = queue;
	vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING |
			    V4L2_CAP_IO_MC;
	video_set_drvdata(vdev, csi);

	ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
	if (ret)
		goto err_entity;

	ret = media_create_pad_link(&csi->subdev.entity, SUN20I_CSI_PAD_SOURCE,
				    &vdev->entity, 0, MEDIA_LNK_FL_ENABLED |
				    MEDIA_LNK_FL_IMMUTABLE);
	if (ret)
		goto err_video;

	return 0;

err_video:
	vb2_video_unregister_device(vdev);
err_entity:
	media_entity_cleanup(&vdev->entity);
	return ret;
}

static int sun20i_csi_runtime_suspend(struct device *dev)
{
	struct sun20i_csi *csi = dev_get_drvdata(dev);

	clk_disable_unprepare(csi->mod_clk);
	clk_disable_unprepare(csi->ram_clk);
	clk_disable_unprepare(csi->bus_clk);
	reset_control_assert(csi->reset);

	return 0;
}

static int sun20i_csi_runtime_resume(struct device *dev)
{
	struct sun20i_csi *csi = dev_get_drvdata(dev);
	int ret;

	ret = reset_control_deassert(csi->reset);
	if (ret)
		return ret;

	ret = clk_prepare_enable(csi->bus_clk);
	if (ret)
		goto err_reset;

	ret = clk_prepare_enable(csi->ram_clk);
	if (ret)
		goto err_bus_clk;

	ret = clk_prepare_enable(csi->mod_clk);
	if (ret)
		goto err_ram_clk;

	return 0;

err_ram_clk:
	clk_disable_unprepare(csi->ram_clk);
err_bus_clk:
	clk_disable_unprepare(csi->bus_clk);
err_reset:
	reset_control_assert(csi->reset);
	return ret;
}

static int sun20i_csi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sun20i_csi *csi;
	int ret;

	csi = devm_kzalloc(dev, sizeof(*csi), GFP_KERNEL);
	if (!csi)
		return -ENOMEM;

	csi->dev = dev;
	platform_set_drvdata(pdev, csi);
	spin_lock_init(&csi->irqlock);
	INIT_LIST_HEAD(&csi->queued);

	ret = devm_mutex_init(dev, &csi->lock);
	if (ret)
		return ret;

	csi->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(csi->regs))
		return PTR_ERR(csi->regs);

	csi->bus_clk = devm_clk_get(dev, "bus");
	if (IS_ERR(csi->bus_clk))
		return dev_err_probe(dev, PTR_ERR(csi->bus_clk),
				     "failed to get the bus clock\n");

	csi->mod_clk = devm_clk_get(dev, "mod");
	if (IS_ERR(csi->mod_clk))
		return dev_err_probe(dev, PTR_ERR(csi->mod_clk),
				     "failed to get the module clock\n");

	csi->ram_clk = devm_clk_get(dev, "ram");
	if (IS_ERR(csi->ram_clk))
		return dev_err_probe(dev, PTR_ERR(csi->ram_clk),
				     "failed to get the DRAM clock\n");

	csi->reset = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(csi->reset))
		return dev_err_probe(dev, PTR_ERR(csi->reset),
				     "failed to get the reset\n");

	ret = devm_clk_rate_exclusive_get(dev, csi->mod_clk);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to lock the module clock rate\n");

	ret = clk_set_rate(csi->mod_clk, SUN20I_CSI_MOD_RATE);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to set the module clock rate\n");

	csi->irq = platform_get_irq(pdev, 0);
	if (csi->irq < 0)
		return csi->irq;

	ret = devm_request_irq(dev, csi->irq, sun20i_csi_irq, 0,
			       dev_name(dev), csi);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request the IRQ\n");

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	csi->mdev.dev = dev;
	strscpy(csi->mdev.model, "Allwinner D1 CSIC", sizeof(csi->mdev.model));
	media_device_init(&csi->mdev);
	csi->v4l2_dev.mdev = &csi->mdev;

	ret = v4l2_device_register(dev, &csi->v4l2_dev);
	if (ret)
		goto err_media;

	/* Check the DT before any device node is created. */
	v4l2_async_nf_init(&csi->notifier, &csi->v4l2_dev);
	csi->notifier.ops = &sun20i_csi_notify_ops;

	ret = sun20i_csi_parse_dt(csi);
	if (ret)
		goto err_notifier;

	ret = sun20i_csi_register_bridge(csi);
	if (ret)
		goto err_notifier;

	ret = sun20i_csi_register_capture(csi);
	if (ret)
		goto err_bridge;

	ret = v4l2_async_nf_register(&csi->notifier);
	if (ret)
		goto err_capture;

	return 0;

err_capture:
	vb2_video_unregister_device(&csi->vdev);
	media_entity_cleanup(&csi->vdev.entity);
err_bridge:
	sun20i_csi_unregister_bridge(csi);
err_notifier:
	v4l2_async_nf_cleanup(&csi->notifier);
	v4l2_device_unregister(&csi->v4l2_dev);
err_media:
	media_device_cleanup(&csi->mdev);
	return ret;
}

static void sun20i_csi_remove(struct platform_device *pdev)
{
	struct sun20i_csi *csi = platform_get_drvdata(pdev);

	/* This stops streaming, which needs the whole pipeline. */
	vb2_video_unregister_device(&csi->vdev);
	media_entity_cleanup(&csi->vdev.entity);
	v4l2_async_nf_unregister(&csi->notifier);
	v4l2_async_nf_cleanup(&csi->notifier);
	sun20i_csi_unregister_bridge(csi);
	media_device_unregister(&csi->mdev);
	v4l2_device_unregister(&csi->v4l2_dev);
	media_device_cleanup(&csi->mdev);
}

/* Runtime PM only: a system sleep must not reset the block while streaming. */
static const struct dev_pm_ops sun20i_csi_pm_ops = {
	RUNTIME_PM_OPS(sun20i_csi_runtime_suspend, sun20i_csi_runtime_resume,
		       NULL)
};

static const struct of_device_id sun20i_csi_of_match[] = {
	{ .compatible = "allwinner,sun20i-d1-csi" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, sun20i_csi_of_match);

static struct platform_driver sun20i_csi_driver = {
	.probe	= sun20i_csi_probe,
	.remove	= sun20i_csi_remove,
	.driver	= {
		.name		= "sun20i-csi",
		.of_match_table	= sun20i_csi_of_match,
		.pm		= pm_ptr(&sun20i_csi_pm_ops),
	},
};
module_platform_driver(sun20i_csi_driver);

MODULE_DESCRIPTION("Allwinner D1/T113 CSIC driver");
MODULE_AUTHOR("Nguyen Minh Tien <tien.nguyenminh@embeddedlinux.blog>");
MODULE_LICENSE("GPL");
