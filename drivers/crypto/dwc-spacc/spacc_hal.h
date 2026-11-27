/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SPACC_HAL_H
#define SPACC_HAL_H

/* maximum number of DDT entries allowed */
#ifndef PDU_MAX_DDT
#define PDU_MAX_DDT		64
#endif

/* platform Generic */
#define PDU_IRQ_EN_GLBL		BIT(31)
#define PDU_IRQ_EN_VSPACC(x)	(1UL << (x))
#define PDU_IRQ_EN_RNG		BIT(16)

#ifndef SPACC_ID_MINOR
	#define SPACC_ID_MINOR(x)		((x)         & 0x0F)
	#define SPACC_ID_MAJOR(x)		(((x) >>  4) & 0x0F)
	#define SPACC_ID_QOS(x)			(((x) >>  8) & 0x01)
	#define SPACC_ID_TYPE(x)		(((x) >>  9) & 0x03)
	#define SPACC_ID_AUX(x)			(((x) >> 11) & 0x01)
	#define SPACC_ID_VIDX(x)		(((x) >> 12) & 0x07)
	#define SPACC_ID_PARTIAL(x)		(((x) >> 15) & 0x01)
	#define SPACC_ID_PROJECT(x)		((x) >> 16)

	#define SPACC_TYPE_SPACCQOS		0
	#define SPACC_TYPE_PDU			1

	#define SPACC_CFG_CTX_CNT(x)		((x) & 0x7F)
	#define SPACC_CFG_RC4_CTX_CNT(x)	(((x) >>  8) & 0x7F)
	#define SPACC_CFG_VSPACC_CNT(x)		(((x) >> 16) & 0x0F)
	#define SPACC_CFG_CIPH_CTX_SZ(x)	(((x) >> 20) & 0x07)
	#define SPACC_CFG_HASH_CTX_SZ(x)	(((x) >> 24) & 0x0F)
	#define SPACC_CFG_DMA_TYPE(x)		(((x) >> 28) & 0x03)

	#define SPACC_CFG_CMD0_FIFO_QOS(x)	(((x) >>  0) & 0x7F)
	#define SPACC_CFG_CMD0_FIFO(x)		(((x) >>  0) & 0x1FF)
	#define SPACC_CFG_CMD1_FIFO(x)		(((x) >>  8) & 0x7F)
	#define SPACC_CFG_CMD2_FIFO(x)		(((x) >> 16) & 0x7F)
	#define SPACC_CFG_STAT_FIFO_QOS(x)	(((x) >> 24) & 0x7F)
	#define SPACC_CFG_STAT_FIFO(x)		(((x) >> 16) & 0x1FF)

	#define SPACC_PDU_CFG_MINOR(x)		((x) & 0x0F)
	#define SPACC_PDU_CFG_MAJOR(x)		(((x) >> 4)  & 0x0F)

	#define PDU_SECURE_LOCK_SPACC(x)	(x)
	#define PDU_SECURE_LOCK_CFG		BIT(30)
	#define PDU_SECURE_LOCK_GLBL		BIT(31)
#endif /* SPACC_ID_MINOR */

struct spacc_version_block {
	unsigned int minor,
		     major,
		     version,
		     qos,
		     is_spacc,
		     is_pdu,
		     aux,
		     vspacc_id,
		     partial,
		     project,
		     ivimport;
};

struct spacc_config_block {
	unsigned int num_ctx,
		     num_vspacc,
		     ciph_ctx_page_size,
		     hash_ctx_page_size,
		     dma_type,
		     cmd0_fifo_depth,
		     cmd1_fifo_depth,
		     cmd2_fifo_depth,
		     stat_fifo_depth;
};

struct pdu_config_block {
	unsigned int minor,
		     major;
};

struct pdu_info {
	u32    clockrate;
	struct spacc_version_block spacc_version;
	struct spacc_config_block  spacc_config;
	struct pdu_config_block    pdu_config;
};

struct pdu_ddt {
	dma_addr_t phys;
	__le32 *virt;
	struct device *dev;
	unsigned long idx, limit, len;
};

void pdu_io_cached_write(struct device *dev, void __iomem *addr,
			 u32 val, u32 *cache);
void pdu_to_dev(void  __iomem *addr, u32 *src, unsigned long nword);
void pdu_from_dev(u32 *dst, void __iomem *addr, unsigned long nword);

void pdu_from_dev_s(unsigned char *dst, void __iomem *addr,
		    unsigned long nword);
void pdu_to_dev_s(void __iomem *addr, const unsigned char *src,
		  unsigned long nword);

int  pdu_mem_init(struct device *device);
void pdu_mem_deinit(struct device *device);
int  pdu_ddt_init(struct device *dev, struct pdu_ddt *ddt, unsigned long limit);
int  pdu_ddt_add(struct device *dev, struct pdu_ddt *ddt, dma_addr_t phys,
		unsigned long size);
int  pdu_ddt_free(struct pdu_ddt *ddt);
int  pdu_get_version(void __iomem *dev, struct pdu_info *inf);
#endif
