/*
 * Copyright (c) 2023 Space Cubics,LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT sc_can

#include <zephyr/kernel.h>
#include <errno.h>
#include <zephyr/drivers/can.h>
#include <zephyr/drivers/can/transceiver.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(sc_can, CONFIG_CAN_LOG_LEVEL);

/* Registers */
#define SCCAN_ENR_OFFSET    (0x0000) /* CAN Enable Register */
#define SCCAN_TQPR_OFFSET   (0x0008) /* CAN Time Quantum Prescaler Register */
#define SCCAN_BTSR_OFFSET   (0x000C) /* CAN Bit Timing Setting Register */
#define SCCAN_ECNTR_OFFSET  (0x0010) /* CAN Error Count Register */
#define SCCAN_STSR_OFFSET   (0x0018) /* CAN Status Register */
#define SCCAN_FIFOSR_OFFSET (0x001C) /* CAN FIFO Status Register */
#define SCCAN_ISR_OFFSET    (0x0020) /* CAN Interrupt Status Register */
#define SCCAN_IER_OFFSET    (0x0024) /* CAN Interrupt Enable Register */
#define SCCAN_TMR1_OFFSET   (0x0030) /* CAN TX Message Register1 */
#define SCCAN_TMR2_OFFSET   (0x0034) /* CAN TX Message Register2 */
#define SCCAN_TMR3_OFFSET   (0x0038) /* CAN TX Message Register3 */
#define SCCAN_TMR4_OFFSET   (0x003C) /* CAN TX Message Register4 */
#define SCCAN_THPMR1_OFFSET (0x0040) /* CAN TX High Priority Message Register1 */
#define SCCAN_THPMR2_OFFSET (0x0044) /* CAN TX High Priority Message Register2 */
#define SCCAN_THPMR3_OFFSET (0x0048) /* CAN TX High Priority Message Register3 */
#define SCCAN_THPMR4_OFFSET (0x004C) /* CAN TX High Priority Message Register4 */
#define SCCAN_RMR1_OFFSET   (0x0050) /* CAN RX Message Register1 */
#define SCCAN_RMR2_OFFSET   (0x0054) /* CAN RX Message Register2 */
#define SCCAN_RMR3_OFFSET   (0x0058) /* CAN RX Message Register3 */
#define SCCAN_RMR4_OFFSET   (0x005C) /* CAN RX Message Register4 */
#define SCCAN_AFER_OFFSET   (0x0060) /* CAN Acceptance Filter Enable Register */
#define SCCAN_AFIMR1_OFFSET (0x0070) /* CAN Acceptance Filter ID Mask Register1 */
#define SCCAN_AFIVR1_OFFSET (0x0074) /* CAN Acceptance Filter ID Value Register1 */
#define SCCAN_AFIMR2_OFFSET (0x0090) /* CAN Acceptance Filter ID Mask Register2 */
#define SCCAN_AFIVR2_OFFSET (0x0094) /* CAN Acceptance Filter ID Value Register2 */
#define SCCAN_AFIMR3_OFFSET (0x00B0) /* CAN Acceptance Filter ID Mask Register3 */
#define SCCAN_AFIVR3_OFFSET (0x00B4) /* CAN Acceptance Filter ID Value Register3 */
#define SCCAN_AFIMR4_OFFSET (0x00D0) /* CAN Acceptance Filter ID Mask Register4 */
#define SCCAN_AFIVR4_OFFSET (0x00D4) /* CAN Acceptance Filter ID Value Register4 */
#define SCCAN_FIFORR_OFFSET (0x00F0) /* CAN FIFO and Buffer Reset Register */
#define SCCAN_STMCR_OFFSET  (0x0100) /* CAN Self Test Mode Control Register */
#define SCCAN_PSLMCR_OFFSET (0x0200) /* CAN PHY Sleep Mode Control Register */
#define SCCAN_VER_OFFSET    (0xF000) /* CAN Controller IP Version Register */

/* CAN Enable Register */
#define SCCAN_EN_DISABLE (0U)
#define SCCAN_EN_ENABLE  (1U)

/* CAN Error Count Register */
#define SCCAN_RXECNT(x) (((x) & GENMASK(15,8)) >> 8)
#define SCCAN_TXECNT(x) (((x) & GENMASK(7,0)))

/* CAN Bit Timing Setting Register */
#define SCCAN_BTSR_SJW(x) ((x) << 7)
#define SCCAN_BTSR_TS2(x) ((x) << 4)
#define SCCAN_BTSR_TS1(x) ((x))

/* CAN Status Register */
#define SCCAN_RXFFL   BIT(7)
#define SCCAN_TXFFL   BIT(6)
#define SCCAN_TXHBFL  BIT(5)
#define SCCAN_TXFNEP  BIT(4)
#define SCCAN_ESTS(x) (((x) & GENMASK(3,2)) >> 2)
#define SCCAN_EWRN    BIT(1)
#define SCCAN_BBUSY   BIT(0)
#define SCCAN_ESTS_CAN_DISABLE   (0b00)
#define SCCAN_ESTS_ERROR_ACTIVE  (0b01)
#define SCCAN_ESTS_ERROR_PASSIVE (0b10)
#define SCCAN_ESTS_BUS_OFF       (0b11)

/* CAN Interrupt Enable Register */
#define SCCAN_BUSOFFENB  BIT(13)
#define SCCAN_ACKERENB   BIT(12)
#define SCCAN_BITERENB   BIT(11)
#define SCCAN_STFERENB   BIT(10)
#define SCCAN_FMERENB    BIT(9)
#define SCCAN_CRCERENB   BIT(8)
#define SCCAN_RXFOVFENB  BIT(7)
#define SCCAN_RXFUDFENB  BIT(6)
#define SCCAN_RXFVALENB  BIT(5)
#define SCCAN_RCVDNENB   BIT(4)
#define SCCAN_TXFOVFENB  BIT(3)
#define SCCAN_TXHBOVFENB BIT(2)
#define SCCAN_ARBLSTENB  BIT(1)
#define SCCAN_TRNSDNENB  BIT(0)

/* CAN Status Register */
#define SCCAN_RXFFL   BIT(7)
#define SCCAN_TXFFL   BIT(6)
#define SCCAN_TXHBFL  BIT(5)
#define SCCAN_TXFNEP  BIT(4)
#define SCCAN_ESTS(x) (((x) & GENMASK(3,2)) >> 2)
#define SCCAN_EWRN    BIT(1)
#define SCCAN_BBUSY   BIT(0)
#define SCCAN_ESTS_CAN_DISABLE   (0b00)
#define SCCAN_ESTS_ERROR_ACTIVE  (0b01)
#define SCCAN_ESTS_ERROR_PASSIVE (0b10)
#define SCCAN_ESTS_BUS_OFF       (0b11)

/* CAN Interrupt Status Register */
#define SCCAN_BUSOFF  BIT(13)
#define SCCAN_ACKER   BIT(12)
#define SCCAN_BITER   BIT(11)
#define SCCAN_STFER   BIT(10)
#define SCCAN_FMER    BIT(9)
#define SCCAN_CRCER   BIT(8)
#define SCCAN_RXFOVF  BIT(7)
#define SCCAN_RXFUDF  BIT(6)
#define SCCAN_RXFVAL  BIT(5)
#define SCCAN_RCVDN   BIT(4)
#define SCCAN_TXFOVF  BIT(3)
#define SCCAN_TXHBOVF BIT(2)
#define SCCAN_ARBLST  BIT(1)
#define SCCAN_TRNSDN  BIT(0)

/* CAN Interrupt Enable Register */
#define SCCAN_IER_ALL_ENA (0x00003FFF)

/* CAN TX Message Register1 */
#define SCCAN_TXID1(x)    (x << 21)
#define SCCAN_TXSRTR(x)   (x << 20)
#define SCCAN_TXIDE(x)    (x << 19)
#define SCCAN_TXID1(x)    (x << 21)
#define SCCAN_TXID_EX1(x) ((x & GENMASK(28,18)) << 3)
#define SCCAN_TXID_EX2(x) ((x & GENMASK(17,0)) << 1)
#define SCCAN_TXERTR(x)   (x)

/* CAN RX Message Register1 */
#define SCCAN_RXID1_STD(x) ((x & GENMASK(31,21)) >> 21)
#define SCCAN_RXID1_EXT(x) ((x & GENMASK(31,21)) >> 3)
#define SCCAN_RXSRTR(x)    ((x & BIT(20)) >> 20)
#define SCCAN_RXIDE(x)     ((x & BIT(19)) >> 19)
#define SCCAN_RXID2_EXT(x) ((x & GENMASK(18,1)) >> 1)
#define SCCAN_RXERTR(x)    (x & BIT(0))

/* CAN RX Message Register2: */
#define SCCAN_DLC(x)  (x & GENMASK(3,0))

/* CAN Acceptance Filter ID Mask Register */
#define SCCAN_AFID1(x)    (x << 21)
#define SCCAN_AFSRTR(x)   (x << 20)
#define SCCAN_AFIDE(x)    (x << 19)
#define SCCAN_AFID1(x)    (x << 21)
#define SCCAN_AFID_EX1(x) ((x & GENMASK(28,18)) << 3)
#define SCCAN_AFID_EX2(x) ((x & GENMASK(17,0)) << 1)
#define SCCAN_AFERTR(x)   (x)

/* CAN FIFO and Buffer Reset Register */
#define SCCAN_FIFORR_TXHPBRST  BIT(17)
#define SCCAN_FIFORR_TXFIFORST BIT(16)
#define SCCAN_FIFORR_RXFIFORST BIT(0)

/* CAN Self Test Mode Control Register */
#define SCCAN_STM_DISABLE (0U)
#define SCCAN_STM_ENABLE  (1U)

/* CAN Controller IP Version Register */
#define SCCAN_VER_MAJOR(x) (((x) & 0xff000000) >> 24)
#define SCCAN_VER_MINOR(x) (((x) & 0x00ff0000) >> 16)
#define SCCAN_VER_PATCH(x) (((x) & 0x0000ffff) >>  0)

/* Timeout configuration for enable/disable CAN */
#define SCCAN_ENABLE_RETRIES    (10)
#define SCCAN_ENABLE_DELAY_USEC K_USEC(10)
#define SCCAN_DISABLE_RETRIES    (10)
#define SCCAN_DISABLE_DELAY_MSEC K_MSEC(10)

/* FIFO DEPTH */
#define SCCAN_TX_FIFO_DEPTH (64U)

typedef void (*irq_init_func_t)(const struct device *dev);

struct sc_can_cfg {
	uint32_t reg_addr;
	irq_init_func_t irq_init;
	uint32_t clock_frequency;
	uint32_t bus_speed;
	uint8_t sjw;
	uint16_t sample_point;
	uint32_t max_bitrate;
};

struct sc_can_data {
	struct k_mutex inst_mutex;
	struct k_sem tx_sem;
	can_tx_callback_t tx_cb[SCCAN_TX_FIFO_DEPTH];
	void *tx_cb_arg[SCCAN_TX_FIFO_DEPTH];
	uint8_t tx_head;
	uint8_t tx_tail;
	can_rx_callback_t rx_cb[CONFIG_CAN_SCCAN_MAX_FILTER];
	void *rx_cb_arg[CONFIG_CAN_SCCAN_MAX_FILTER];
	struct can_filter rx_filter[CONFIG_CAN_SCCAN_MAX_FILTER];
	can_state_change_callback_t state_change_cb;
	void *state_change_cb_data;
	enum can_state state;
};

static inline uint32_t sc_can_read32(const struct sc_can_cfg *config, uint32_t offset)
{
	return sys_read32(config->reg_addr + offset);
}

static inline void sc_can_write32(const struct sc_can_cfg *config, uint32_t offset, uint32_t value)
{
	return sys_write32(value, config->reg_addr + offset);
}

static bool sc_can_is_enabled(const struct sc_can_cfg *config)
{
	uint32_t status_reg;

	status_reg = sc_can_read32(config, SCCAN_STSR_OFFSET);
	if (SCCAN_ESTS(status_reg) == SCCAN_ESTS_CAN_DISABLE) {
		return false;
	} else {
		return true;
	}
}

static int sc_can_enable(const struct sc_can_cfg *config)
{
	int retries = SCCAN_ENABLE_RETRIES;

	/*
	 * When set the CAN_EN register to `Enable`, it becomes an ERROR_ACTIVE
	 * state after detecting consecutive 11-bit recessive on the CAN bus.
	 */
	sc_can_write32(config, SCCAN_ENR_OFFSET, SCCAN_EN_ENABLE);
	while (!sc_can_is_enabled(config)) {
		if (--retries < 0) {
			LOG_ERR("Timeout trying to enable CAN");
			return -EIO;
		}

		k_sleep(SCCAN_ENABLE_DELAY_USEC);
	}

	return 0;
}

static inline bool sc_can_filter_is_used(const struct sc_can_cfg *config, int filter_id)
{
	if ((sc_can_read32(config, SCCAN_AFER_OFFSET) & BIT(filter_id))) {
		return true;
	} else {
		return false;
	}
}

static int sc_can_disable(const struct sc_can_cfg *config)
{
	int retries = SCCAN_DISABLE_RETRIES;

	/*
	 * If CAN Controller is sending or receiving the frame,
	 * writing of CAN DISABLE register might not be reflected,
	 * so retry a certain number of times until confirm disabled CAN.
	 */
	sc_can_write32(config, SCCAN_ENR_OFFSET, SCCAN_EN_DISABLE);
	while (sc_can_is_enabled(config)) {
		if (--retries < 0) {
			LOG_ERR("Timeout trying to disable CAN");
			return -EBUSY;
		}

		k_sleep(SCCAN_DISABLE_DELAY_MSEC);
		sc_can_write32(config, SCCAN_ENR_OFFSET, SCCAN_EN_DISABLE);
	}

	return 0;
}

static uint32_t sc_can_get_idr(uint32_t id, bool extended, bool rtr)
{
	uint32_t idr;

	if (extended) {
		idr = (SCCAN_TXID_EX1(id) | SCCAN_TXSRTR(1) | SCCAN_TXIDE(extended) |
		       SCCAN_TXID_EX2(id) | SCCAN_TXERTR(rtr));
	} else {
		idr = (SCCAN_TXID1(id) | SCCAN_TXSRTR(rtr) | SCCAN_TXIDE(extended));
	}

	return idr;
}

static void sc_can_tx_done(const struct device *dev, int status)
{
	struct sc_can_data *data = dev->data;
	can_tx_callback_t callback;

	callback = data->tx_cb[data->tx_tail];
	if (callback != NULL) {
		callback(dev, status, data->tx_cb_arg[data->tx_tail]);
		data->tx_cb[data->tx_tail] = NULL;

		data->tx_tail++;
		if (data->tx_tail == SCCAN_TX_FIFO_DEPTH) {
			data->tx_tail = 0;
		}

		k_sem_give(&data->tx_sem);
	}
}

static void sc_can_enable_acceptance_filter(const struct sc_can_cfg *config,
					     int filter_id, const struct can_filter *filter)
{
	uint32_t mask_offset;
	uint32_t value_offset;
	uint32_t enable_reg;
	uint32_t mask_reg = 0;
	uint32_t value_reg = 0;
	bool extended = filter->flags & CAN_FILTER_IDE;
	bool rtr = filter->flags & CAN_FILTER_RTR;

	mask_offset = SCCAN_AFIMR1_OFFSET + (filter_id * 0x20);
	value_offset = SCCAN_AFIVR1_OFFSET + (filter_id * 0x20);

	/* Enable Acceptance Filter */
	enable_reg = sc_can_read32(config, SCCAN_AFER_OFFSET);
	sc_can_write32(config, SCCAN_AFER_OFFSET, enable_reg | BIT(filter_id));

	/* Regist Acceptance Filter Mask and Value */
	if (filter->flags & CAN_FILTER_IDE) {
		mask_reg = (SCCAN_AFID_EX1(filter->mask) | SCCAN_AFSRTR(1) | SCCAN_AFIDE(extended) |
					SCCAN_AFID_EX2(filter->mask) | SCCAN_AFERTR(rtr));
		value_reg = (SCCAN_AFID_EX1(filter->id) | SCCAN_AFSRTR(1) | SCCAN_AFIDE(extended) |
					SCCAN_AFID_EX2(filter->id) | SCCAN_AFERTR(rtr));
	} else {
		mask_reg = (SCCAN_TXID1(filter->mask) | SCCAN_AFSRTR(rtr) | SCCAN_AFIDE(extended));
		value_reg = (SCCAN_TXID1(filter->id) | SCCAN_AFSRTR(rtr) | SCCAN_AFIDE(extended));
	}

	sc_can_write32(config, mask_offset, mask_reg);
	sc_can_write32(config, value_offset, value_reg);

	return;
}

static void sc_can_read_idr(const struct sc_can_cfg *config, struct can_frame *can_frame)
{
	uint32_t idr;

	idr = sc_can_read32(config, SCCAN_RMR1_OFFSET);

	if (SCCAN_RXIDE(idr)) {
		can_frame->id = (SCCAN_RXID1_EXT(idr) | SCCAN_RXID2_EXT(idr));
		can_frame->flags |= CAN_FRAME_IDE;
		if (SCCAN_RXERTR(idr)) {
			can_frame->flags |= CAN_FRAME_RTR;
		}
	} else {
		can_frame->id = SCCAN_RXID1_STD(idr);
		if (SCCAN_RXSRTR(idr)) {
			can_frame->flags |= CAN_FRAME_RTR;
		}
	}

	return;
}

static void sc_can_rx_cb(const struct device *dev, struct can_frame *frame)
{
	struct sc_can_data *data = dev->data;
	uint8_t filter_id;

	/* In this driver, called the all RX callback that matched registered filter */
	for (filter_id = 0; filter_id < CONFIG_CAN_SCCAN_MAX_FILTER; filter_id++) {
		if (data->rx_cb[filter_id] == NULL) {
			continue;
		}

		if (can_frame_matches_filter(frame, &data->rx_filter[filter_id])) {
			data->rx_cb[filter_id](dev, frame, data->rx_cb_arg[filter_id]);
			LOG_DBG("Filter matched. ID: %d", filter_id);
		}
	}

	return;
}

static void sc_can_rx_isr(const struct device *dev)
{
	const struct sc_can_cfg *config = dev->config;
	struct can_frame frame = {0};
	uint32_t data0_reg;
	uint32_t data1_reg;

	/* Read CAN IDR from RMR1 */
	sc_can_read_idr(config, &frame);

	/* Read DLC from RMR2 */
	frame.dlc = SCCAN_DLC(sc_can_read32(config, SCCAN_RMR2_OFFSET));

	/* RMR3/RMR4 must be read to clear the FIFO regardless of the dlc */
	data0_reg = sc_can_read32(config, SCCAN_RMR3_OFFSET);
	frame.data_32[0] = sys_cpu_to_be32(data0_reg);

	data1_reg = sc_can_read32(config, SCCAN_RMR4_OFFSET);
	frame.data_32[1] = sys_cpu_to_be32(data1_reg);

	LOG_DBG("Receiving %d bytes. Id: 0x%x, ID type: %s %s",
		frame.dlc, frame.id,
		(frame.flags & CAN_FRAME_IDE) != 0 ? "extended" : "standard",
		(frame.flags & CAN_FRAME_RTR) != 0 ? ", RTR frame" : "");

	/* Callback for specificed filter */
	sc_can_rx_cb(dev, &frame);

	return;
}

static void sc_can_get_error_count(const struct sc_can_cfg *config,
			      struct can_bus_err_cnt *err_cnt)
{
	uint32_t errcnt_reg;

	errcnt_reg = sc_can_read32(config, SCCAN_ECNTR_OFFSET);
	err_cnt->tx_err_cnt = SCCAN_TXECNT(errcnt_reg);
	err_cnt->rx_err_cnt = SCCAN_RXECNT(errcnt_reg);
}

static int sc_can_get_state(const struct device *dev, enum can_state *state,
			      struct can_bus_err_cnt *err_cnt)
{
	const struct sc_can_cfg *config = dev->config;
	uint32_t status_reg;

	status_reg = sc_can_read32(config, SCCAN_STSR_OFFSET);
	switch (SCCAN_ESTS(status_reg)) {
		case SCCAN_ESTS_CAN_DISABLE:
			*state = CAN_STATE_STOPPED;
			break;
		case SCCAN_ESTS_ERROR_ACTIVE:
			if (status_reg & SCCAN_EWRN) {
				*state = CAN_STATE_ERROR_WARNING;
			} else {
				*state = CAN_STATE_ERROR_ACTIVE;
			}
			break;
		case SCCAN_ESTS_ERROR_PASSIVE:
			*state = CAN_STATE_ERROR_PASSIVE;
			break;
		case SCCAN_ESTS_BUS_OFF:
		default:
			*state = CAN_STATE_BUS_OFF;
			break;
	}

	sc_can_get_error_count(config, err_cnt);

	return 0;
}

static void sc_can_state_change(const struct device *dev)
{
	struct sc_can_data *data = dev->data;
	const can_state_change_callback_t cb = data->state_change_cb;
	void *user_data = data->state_change_cb_data;
	struct can_bus_err_cnt err_cnt;
	enum can_state new_state;

	if (sc_can_get_state(dev, &new_state, &err_cnt) < 0) {
		return;
	}

	if (data->state == new_state) {
		return;
	}

	LOG_DBG("Can state change new: %u, old: %u", new_state, data->state);

	if (cb == NULL) {
		return;
	}

	data->state = new_state;
	cb(dev, new_state, err_cnt, user_data);
}

static void sc_can_isr(const struct device *dev)
{
	const struct sc_can_cfg *config = dev->config;
	uint32_t isr;

	isr = sc_can_read32(config, SCCAN_ISR_OFFSET);
	LOG_DBG("IRQ Status 0x%08x", isr);

	sc_can_write32(config, SCCAN_ISR_OFFSET, isr);

	if (isr & SCCAN_BUSOFF) {
		sc_can_state_change(dev);
	}
	if (isr & SCCAN_ACKER) {
		CAN_STATS_ACK_ERROR_INC(dev);
		sc_can_tx_done(dev, SCCAN_ACKER);
	}
	if (isr & SCCAN_BITER) {
		/* SC CAN does not distinguish between BIT0 and 1 errors,
		 * so it counts on BIT0. */
		CAN_STATS_BIT0_ERROR_INC(dev);
		sc_can_tx_done(dev, SCCAN_BITER);
	}
	if (isr & SCCAN_STFER) {
	}
	if (isr & SCCAN_FMER) {
	}
	if (isr & SCCAN_CRCER) {
	}
	if (isr & SCCAN_RXFOVF) {
	}
	if (isr & SCCAN_RXFUDF) {
	}
	if (isr & SCCAN_RXFVAL) {
		sc_can_rx_isr(dev);
	}
	if (isr & SCCAN_RCVDN) {
	}
	if (isr & SCCAN_TXFOVF) {
		sc_can_tx_done(dev, SCCAN_TXFOVF);
	}
	if (isr & SCCAN_TXHBOVF) {
		/* TX High Priority Buffer is not used yet */
	}
	if (isr & SCCAN_ARBLST) {
		sc_can_tx_done(dev, SCCAN_ARBLST);
	}
	if (isr & SCCAN_TRNSDN) {
		sc_can_tx_done(dev, 0);
	}
}

static int sc_can_get_capabilities(const struct device *dev, can_mode_t *cap)
{
	ARG_UNUSED(dev);

	*cap = CAN_MODE_NORMAL | CAN_MODE_LOOPBACK;

	return 0;
}

static int sc_can_start(const struct device *dev)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	int ret;

	if (sc_can_is_enabled(config)) {
		return -EALREADY;
	}

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	ret = sc_can_enable(config);

	if (ret == 0) {
		/* Notify state change to callback, if enabled */
		sc_can_state_change(dev);
	}

	k_mutex_unlock(&data->inst_mutex);

	return ret;
}

static int sc_can_stop(const struct device *dev)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	int ret;

	if (!sc_can_is_enabled(config)) {
		return -EALREADY;
	}

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	ret = sc_can_disable(config);

	if (ret == 0) {
		/* Clear all FIFO if disabled */
		sc_can_write32(config, SCCAN_FIFORR_OFFSET,
			  SCCAN_FIFORR_TXHPBRST |
			  SCCAN_FIFORR_TXFIFORST |
			  SCCAN_FIFORR_RXFIFORST);

		/* Notify the disable CAN to all TX callback */
		for (int i = 0; i < SCCAN_TX_FIFO_DEPTH; i++) {
			sc_can_tx_done(dev, -ENETDOWN);
		}

		/* Notify state change to callback */
		sc_can_state_change(dev);
	}

	k_mutex_unlock(&data->inst_mutex);

	return ret;
}

static int sc_can_set_mode(const struct device *dev, can_mode_t mode)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	uint32_t mode_reg = 0;

	if ((mode & ~CAN_MODE_LOOPBACK) != 0) {
		LOG_ERR("Unsupported mode: 0x%08x", mode);
		return -ENOTSUP;
	}

	if (sc_can_is_enabled(config)) {
		return -EBUSY;
	}

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	if ((mode & CAN_MODE_LOOPBACK) != 0) {
		/* Self Test Mode */
		mode_reg = SCCAN_STM_ENABLE;
	} else {
		/* Normal Mode */
		mode_reg = SCCAN_STM_DISABLE;
	}

	sc_can_write32(config, SCCAN_STMCR_OFFSET, mode_reg);

	k_mutex_unlock(&data->inst_mutex);

	LOG_DBG("Set mode:%d", mode);

	return 0;
}

static int sc_can_set_timing(const struct device *dev,
			       const struct can_timing *timing)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	uint32_t timing_reg = 0;

	/* Must be disabled to set timing */
	if (sc_can_is_enabled(config)) {
		LOG_ERR("Failed to set timing because enabled CAN");
		return -EBUSY;
	}

	LOG_DBG("Presc: %d, TS1: %d, TS2: %d, SJW: %d",
			timing->prescaler, timing->phase_seg1, timing->phase_seg2, timing->sjw);

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	/* Set Time Quantum Prescaler Register */
	sc_can_write32(config, SCCAN_TQPR_OFFSET, timing->prescaler -1);

	/* Set Bit Timing Setting Register */
	timing_reg |= SCCAN_BTSR_TS1(timing->prop_seg + timing->phase_seg1 - 1);
	timing_reg |= SCCAN_BTSR_TS2(timing->phase_seg2 - 1);
	if (timing->sjw != CAN_SJW_NO_CHANGE) {
		timing_reg |= SCCAN_BTSR_SJW(timing->sjw - 1);
	} else {
		timing_reg |= SCCAN_BTSR_SJW(config->sjw - 1);
	}
	sc_can_write32(config, SCCAN_BTSR_OFFSET, timing_reg);

	k_mutex_unlock(&data->inst_mutex);

	return 0;
}

static void sc_can_set_state_change_callback(const struct device *dev,
					       can_state_change_callback_t cb,
					       void *user_data)
{
	struct sc_can_data *data = dev->data;

	data->state_change_cb = cb;
	data->state_change_cb_data = user_data;
}

#ifndef CONFIG_CAN_AUTO_BUS_OFF_RECOVERY
static int sc_can_recover(const struct device *dev, k_timeout_t timeout)
{
	const struct sc_can_cfg *config = dev->config;

	ARG_UNUSED(timeout);

	if (!sc_can_is_enabled(config)) {
		return -ENETDOWN;
	}

	return 0;
}
#endif /* CONFIG_CAN_AUTO_BUS_OFF_RECOVERY */

static int sc_can_send(const struct device *dev, const struct can_frame *frame,
			 k_timeout_t timeout, can_tx_callback_t callback,
			 void *user_data)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	uint32_t idr;

	__ASSERT_NO_MSG(callback != NULL);

	LOG_DBG("Sending %d bytes on %s. Id: 0x%x, ID type: %s %s",
		frame->dlc, dev->name, frame->id,
		(frame->flags & CAN_FRAME_IDE) != 0 ? "extended" : "standard",
		(frame->flags & CAN_FRAME_RTR) != 0 ? ", RTR frame" : "");

	if (frame->dlc > CAN_MAX_DLC) {
		LOG_ERR("DLC of %d exceeds maximum (%d)",
			frame->dlc, CAN_MAX_DLC);
		return -EINVAL;
	}

	if ((frame->flags & ~(CAN_FRAME_IDE | CAN_FRAME_RTR)) != 0) {
		LOG_ERR("unsupported CAN frame flags 0x%02x", frame->flags);
		return -ENOTSUP;
	}

	/* Check if the TX buffer is full */
	if (k_sem_take(&data->tx_sem, timeout) != 0) {
		return -EAGAIN;
	}

	if (!sc_can_is_enabled(config)) {
		return -ENETDOWN;
	}

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	/* Write CAN IDR to TMR1 */
	idr = sc_can_get_idr(frame->id, (frame->flags & CAN_FRAME_IDE), (frame->flags & CAN_FRAME_RTR));
	sc_can_write32(config, SCCAN_TMR1_OFFSET, idr);

	/* Write DLC to TMR2 */
	sc_can_write32(config, SCCAN_TMR2_OFFSET, frame->dlc);

	/* Write CAN Data Frame to TMR3/TMR4 */
	sc_can_write32(config, SCCAN_TMR3_OFFSET, sys_be32_to_cpu(frame->data_32[0]));
	sc_can_write32(config, SCCAN_TMR4_OFFSET, sys_be32_to_cpu(frame->data_32[1]));

	/* Save call back function */
	data->tx_cb[data->tx_head] = callback;
	data->tx_cb_arg[data->tx_head] = user_data;
	data->tx_head++;
	if (data->tx_head == SCCAN_TX_FIFO_DEPTH) {
		data->tx_head  = 0;
	}

	k_mutex_unlock(&data->inst_mutex);

	return 0;
}

/*
 * SC CAN controller has four "Acceptance filter" feature, so this driver use
 * it as the "RX filter".
 * And, due to the specifications of the SC CAN controller, Acceptance Filter
 * can only be set when disable CAN.
 * However, Zephyr specification don't defines the timing for adding/removing
 * RX filter. In fact, CAN sample application (samples/drivers/can/counter) is
 * called can_add_rx_filter_msgq() after can_start().
 * Therefore, in this driver, temporarily disabled CAN and set
 * "Acceptance filer" to SC CAN controller.
 */
static int sc_can_add_rx_filter(const struct device *dev, can_rx_callback_t cb,
				  void *cb_arg, const struct can_filter *filter)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	bool do_disable = false;
	int ret = 0;
	int filter_id;

	LOG_DBG("Setting filter ID: 0x%x, mask: 0x%x", filter->id, filter->mask);

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	if (sc_can_is_enabled(config)) {
		/* Disable CAN with retry if enabled */
		ret = sc_can_disable(config);
		if (ret != 0) {
			goto unlock;
		}
		do_disable = true;
	}

	ret = -ENOSPC;
	for (filter_id = 0; filter_id < CONFIG_CAN_SCCAN_MAX_FILTER; filter_id++) {
		if (!sc_can_filter_is_used(config, filter_id)) {
			sc_can_enable_acceptance_filter(config, filter_id, filter);

			data->rx_cb[filter_id] = cb;
			data->rx_cb_arg[filter_id] = cb_arg;
			data->rx_filter[filter_id] = *filter;
			ret = filter_id;
			break;
		}
	}

	if (filter_id == CONFIG_CAN_SCCAN_MAX_FILTER) {
		LOG_ERR("No free filter left");
	} else {
		LOG_DBG("Filter added. ID: %d", filter_id);
	}

	if (do_disable) {
		/* Enable CAN if disabled in this API */
		sc_can_enable(config);
	}

unlock:
	k_mutex_unlock(&data->inst_mutex);

	return ret;
}

static void sc_can_remove_rx_filter(const struct device *dev, int filter_id)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	int ret;
	uint32_t enable_reg;
	bool do_disable = false;

	if (filter_id >= CONFIG_CAN_SCCAN_MAX_FILTER) {
		LOG_ERR("Filter ID of %d exceeds maximum (%d)",
			filter_id, CONFIG_CAN_SCCAN_MAX_FILTER);
		return;
	}

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	if (sc_can_is_enabled(config)) {
		/* Disable CAN with retry if enabled */
		ret = sc_can_disable(config);
		if (ret != 0) {
			goto unlock;
		}
		do_disable = true;
	}

	enable_reg = sc_can_read32(config, SCCAN_AFER_OFFSET);
	enable_reg &= ~BIT(filter_id);
	sc_can_write32(config, SCCAN_AFER_OFFSET, enable_reg);
	data->rx_cb[filter_id] = NULL;
	LOG_DBG("Filter removed. ID: %d", filter_id);

	if (do_disable) {
		/* Enable CAN if disabled in this API */
		sc_can_enable(config);
	}

unlock:
	k_mutex_unlock(&data->inst_mutex);

	return;
}

static int sc_can_init(const struct device *dev)
{
	const struct sc_can_cfg *config = dev->config;
	struct sc_can_data *data = dev->data;
	struct can_timing timing;
	int32_t ret;
	uint32_t v;

	k_mutex_init(&data->inst_mutex);
	k_sem_init(&data->tx_sem, SCCAN_TX_FIFO_DEPTH, SCCAN_TX_FIFO_DEPTH);

	data->tx_head = 0;
	data->tx_tail = 0;

	memset(data->rx_cb, 0, sizeof(data->rx_cb));

	data->state = CAN_STATE_STOPPED;
	data->state_change_cb = NULL;

	/* Set timing according to dts default setting */
	timing.sjw = config->sjw;
	ret = can_calc_timing(dev, &timing, config->bus_speed, config->sample_point);
	if (ret == -EINVAL) {
		LOG_ERR("Can't find timing for given param");
		return -EIO;
	}
	sc_can_set_timing(dev, &timing);

	/* Enable all IRQ */
	sc_can_write32(config, SCCAN_IER_OFFSET,
			  SCCAN_BUSOFFENB |
			  SCCAN_ACKERENB |
			  SCCAN_BITERENB |
			  SCCAN_STFERENB |
			  SCCAN_FMERENB |
			  SCCAN_CRCERENB |
			  SCCAN_RXFOVFENB |
			  SCCAN_RXFUDFENB |
			  SCCAN_RXFVALENB |
			  SCCAN_RCVDNENB |
			  SCCAN_TXFOVFENB |
			  SCCAN_TXHBOVFENB |
			  SCCAN_ARBLSTENB |
			  SCCAN_TRNSDNENB);
	config->irq_init(dev);

	/* Dump Version information */
	v = sc_can_read32(config, SCCAN_VER_OFFSET);
	LOG_DBG("Space Cubics CAN controller v%d.%d.%d initialized",
		   SCCAN_VER_MAJOR(v), SCCAN_VER_MINOR(v), SCCAN_VER_PATCH(v));

	return 0;
}

static int sc_can_get_core_clock(const struct device *dev, uint32_t *rate)
{
	const struct sc_can_cfg *config = dev->config;

	*rate = config->clock_frequency;

	return 0;
}

/*
 * This API specification is here:
 *   Get the maximum standard (11-bit) CAN ID filters if false, or extended (29-bit)
 *   CAN ID filters if true
 * Acceptance filter of SC CAN Controller supports both standard and extended, so
 * always returns the same value.
 */
static int sc_can_get_max_filters(const struct device *dev, bool ide)
{
	ARG_UNUSED(ide);

	return CONFIG_CAN_SCCAN_MAX_FILTER;
}

static int sc_can_get_max_bitrate(const struct device *dev, uint32_t *max_bitrate)
{
	const struct sc_can_cfg *config = dev->config;

	*max_bitrate = config->max_bitrate;

	return 0;
}

static const struct can_driver_api sc_can_driver_api = {
	.get_capabilities = sc_can_get_capabilities,
	.start = sc_can_start,
	.stop = sc_can_stop,
	.set_mode = sc_can_set_mode,
	.set_timing = sc_can_set_timing,
	.send = sc_can_send,
	.add_rx_filter = sc_can_add_rx_filter,
	.remove_rx_filter = sc_can_remove_rx_filter,
	.get_state = sc_can_get_state,
#ifndef CONFIG_CAN_AUTO_BUS_OFF_RECOVERY
	.recover = sc_can_recover,
#endif
	.set_state_change_callback = sc_can_set_state_change_callback,
	.get_core_clock = sc_can_get_core_clock,
	.get_max_filters = sc_can_get_max_filters,
	.get_max_bitrate = sc_can_get_max_bitrate,
	.timing_min = {
		.sjw = 0x1,
		.prop_seg = 0x00,
		.phase_seg1 = 0x04,
		.phase_seg2 = 0x02,
		.prescaler = 0x01
	},
	.timing_max = {
		.sjw = 0x4,
		.prop_seg = 0x00,
		.phase_seg1 = 0x10,
		.phase_seg2 = 0x08,
		.prescaler = 0x400
	}
};

#define SCCAN_INIT(n)								\
	static void sc_can_##n##_irq_init(const struct device *dev);		\
	static const struct sc_can_cfg sc_can_cfg_##n = {			\
		.reg_addr = DT_INST_REG_ADDR(n),				\
		.irq_init = sc_can_##n##_irq_init,				\
		.clock_frequency = DT_INST_PROP(n, clock_frequency),		\
		.bus_speed = DT_INST_PROP(n, bus_speed),			\
		.sjw = DT_INST_PROP(n, sjw),					\
		.sample_point = DT_INST_PROP(n, sample_point),			\
		.max_bitrate = DT_INST_CAN_TRANSCEIVER_MAX_BITRATE(n, 1000000),	\
	};									\
	static struct sc_can_data sc_can_data_##n;				\
	CAN_DEVICE_DT_INST_DEFINE(n, sc_can_init,				\
				  NULL,						\
				  &sc_can_data_##n,				\
				  &sc_can_cfg_##n,				\
				  POST_KERNEL,					\
				  CONFIG_CAN_INIT_PRIORITY,			\
				  &sc_can_driver_api				\
				  );						\
	static void sc_can_##n##_irq_init(const struct device *dev)		\
	{									\
		IRQ_CONNECT(DT_INST_IRQN(n),					\
			    0,							\
			    sc_can_isr,						\
			    DEVICE_DT_INST_GET(n), 0);				\
										\
		irq_enable(DT_INST_IRQN(n));					\
	}


DT_INST_FOREACH_STATUS_OKAY(SCCAN_INIT)
