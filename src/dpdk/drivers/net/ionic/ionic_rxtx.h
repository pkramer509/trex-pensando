/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#ifndef _IONIC_RXTX_H_
#define _IONIC_RXTX_H_

#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "ionic_if.h"
#include "ionic_lif.h"

struct ionic_rx_service {
	/* cb in */
	struct rte_mbuf **rx_pkts;
	/* cb out */
	uint16_t nb_rx;
};

#define IONIC_CSUM_FLAG_MASK	(IONIC_RXQ_COMP_CSUM_F_VLAN - 1)
#define IONIC_PREFETCH

extern const uint64_t ionic_csum_flags[IONIC_CSUM_FLAG_MASK];
extern const uint32_t ionic_ptype_table[IONIC_RXQ_COMP_PKT_TYPE_MASK];

/* ionic_rxtx.c */
int ionic_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
	uint16_t nb_desc, uint32_t socket_id,
	const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp);
void ionic_dev_rx_queue_release(void *rxq);
int ionic_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);
int ionic_dev_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id);

int ionic_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
	uint16_t nb_desc,  uint32_t socket_id,
	const struct rte_eth_txconf *tx_conf);
void ionic_dev_tx_queue_release(void *tx_queue);
int ionic_dev_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id);
int ionic_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);

void ionic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo);
void ionic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo);

int ionic_dev_rx_descriptor_done(void *rx_queue, uint16_t offset);
int ionic_dev_rx_descriptor_status(void *rx_queue, uint16_t offset);
int ionic_dev_tx_descriptor_status(void *tx_queue, uint16_t offset);

const uint32_t *ionic_dev_supported_ptypes_get(struct rte_eth_dev *dev);

int ionic_tx_tso(struct ionic_tx_qcq *txq, struct rte_mbuf *txm);

uint16_t ionic_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);

/* ionic_rxtx_simple.c */
uint16_t ionic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts);
uint16_t ionic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);

int ionic_rx_fill(struct ionic_rx_qcq *rxq);

/* ionic_rxtx_sg.c */
uint16_t ionic_recv_pkts_sg(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts);
uint16_t ionic_xmit_pkts_sg(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);

int ionic_rx_fill_sg(struct ionic_rx_qcq *rxq);

#if defined(IONIC_CODE_PERF_RX) || defined(IONIC_CODE_PERF_TX)
static inline uint64_t
ionic_tsc(void)
{
	uint64_t tsc;
#ifdef RTE_ARCH_ARM64
	asm volatile("mrs %0, pmccntr_el0" : "=r"(tsc));
#else
	tsc = rte_get_tsc_cycles();
#endif
	return tsc;
}
#endif /* defined(IONIC_CODE_PERF_RX) || defined(IONIC_CODE_PERF_TX) */

#endif /* _IONIC_RXTX_H_ */
