// SPDX-License-Identifier: GPL-2.0
/*
 * URMA Kernel Module Demo - Client
 *
 * This module demonstrates URMA kernel API usage as a client:
 * 1. Registers a 16KB memory region
 * 2. Sends segment information to the server
 * 3. Waits for server to perform RDMA read and send CRC32 reply
 *
 * Copyright (c) 2024
 */

#define pr_fmt(fmt) "client: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/ummu_core.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/inet.h>

#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include <uapi/ub/urma/udma/udma_abi.h>

#include "urma_demo_common.h"

#define URMA_CLIENT_NAME "urma_demo_client"
#define URMA_CLIENT_DATA_PAGE_COUNT (URMA_DEMO_CLIENT_BUF_SIZE / PAGE_SIZE)

/* Module parameters */
static char *server_eid = "";
module_param(server_eid, charp, 0444);
MODULE_PARM_DESC(
	server_eid,
	"Server EID in format xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx");

static unsigned int server_jetty = URMA_DEMO_SERVER_JETTY_ID;
module_param(server_jetty, uint, 0444);
MODULE_PARM_DESC(server_jetty, "Server jetty ID (default: " __stringify(
				       URMA_DEMO_SERVER_JETTY_ID) ")");

static unsigned int client_jetty = URMA_DEMO_CLIENT_JETTY_ID;
module_param(client_jetty, uint, 0444);
MODULE_PARM_DESC(client_jetty, "Client jetty ID (default: " __stringify(
				       URMA_DEMO_CLIENT_JETTY_ID) ")");

static char *device_name = "";
module_param(device_name, charp, 0444);
MODULE_PARM_DESC(device_name,
		 "URMA device name (optional, uses first available if not set)");

static char *local_eid = "";
module_param(local_eid, charp, 0444);
MODULE_PARM_DESC(
	local_eid,
	"Local EID to select EID index (optional, format: xx:xx:...:xx)");

/* Client context structure */
struct urma_client_ctx {
	/* Device and client registration */
	struct ubcore_device *ub_dev;
	struct ubcore_client ub_client;

	/* Resources */
	struct ubcore_jfc *jfc;
	struct ubcore_jfr *jfr;
	struct ubcore_jetty *jetty;

	/* Remote connection */
	struct ubcore_tjetty *tjetty;
	u8 server_eid_raw[URMA_DEMO_EID_SIZE];

	/* Buffers */
	struct page *data_pages[URMA_CLIENT_DATA_PAGE_COUNT];
	struct device *data_tdev;
	struct iommu_domain *data_domain;
	struct sg_table data_sgt;
	struct scatterlist data_sgl[URMA_CLIENT_DATA_PAGE_COUNT];
	bool data_mapt_granted;
	bool data_dma_mapped;
	dma_addr_t data_iova;
	u32 data_iova_len;
	u32 data_tid;
	u32 data_token_id;
	u32 data_token_value;
	u32 data_crc32;
	void *send_buf; /* Send message buffer */
	void *recv_buf; /* Receive buffer for reply */
	struct ubcore_target_seg *send_seg;
	struct ubcore_target_seg *recv_seg;

	/* SGEs */
	struct ubcore_sge send_sge;
	struct ubcore_sge recv_sge;

	/* State */
	bool initialized;
	bool connected;
	u32 eid_index;
};

static struct urma_client_ctx g_client_ctx;
static DEFINE_MUTEX(urma_demo_mapt_mutex);

static const struct iommu_perm_ops *
urma_demo_domain_perm_ops(struct iommu_domain *domain)
{
#ifdef CONFIG_IOMMU_KSVA
	return domain ? domain->perm_ops : NULL;
#else
	return NULL;
#endif
}

static int urma_demo_domain_grant(struct iommu_domain *domain, u64 iova,
				  size_t len, int perm, void *cookie)
{
	const struct iommu_perm_ops *perm_ops =
		urma_demo_domain_perm_ops(domain);
	struct iommu_plb_gather gather = {};
	int ret;

	if (!perm_ops || !perm_ops->grant)
		return -EOPNOTSUPP;

	mutex_lock(&urma_demo_mapt_mutex);
	ret = perm_ops->grant(domain, (void *)(uintptr_t)iova, len, perm,
			      cookie, &gather);
	iommu_plb_sync(domain, &gather);
	mutex_unlock(&urma_demo_mapt_mutex);

	return ret;
}

static int urma_demo_domain_ungrant(struct iommu_domain *domain, u64 iova,
				    size_t len, void *cookie)
{
	const struct iommu_perm_ops *perm_ops =
		urma_demo_domain_perm_ops(domain);
	struct iommu_plb_gather gather = {};
	int ret;

	if (!perm_ops || !perm_ops->ungrant)
		return -EOPNOTSUPP;

	mutex_lock(&urma_demo_mapt_mutex);
	ret = perm_ops->ungrant(domain, (void *)(uintptr_t)iova, len, cookie,
				&gather);
	iommu_plb_sync(domain, &gather);
	mutex_unlock(&urma_demo_mapt_mutex);

	return ret;
}

static int urma_client_alloc_data_tdev(struct urma_client_ctx *ctx)
{
	const struct iommu_perm_ops *perm_ops;
	struct tdev_attr attr;
	u32 tid = UMMU_INVALID_TID;
	int ret;

	tdev_attr_init(&attr);
	attr.name = "urma-demo-data";
	attr.mode = MAPT_MODE_TABLE;

	ctx->data_tdev = ummu_core_alloc_tdev(&attr, &tid);
	if (!ctx->data_tdev) {
		pr_err("%s: failed to allocate data tdev\n", URMA_CLIENT_NAME);
		return -ENODEV;
	}

	ctx->data_domain = iommu_get_domain_for_dev(ctx->data_tdev);
	if (!ctx->data_domain) {
		pr_err("%s: data tdev has no IOMMU domain\n",
		       URMA_CLIENT_NAME);
		ret = -ENODEV;
		goto err_free_tdev;
	}

	if (!ctx->data_domain->ops || !ctx->data_domain->ops->map_pages) {
		pr_err("%s: data tdev domain does not support page mappings\n",
		       URMA_CLIENT_NAME);
		ret = -EOPNOTSUPP;
		goto err_free_tdev;
	}

	perm_ops = urma_demo_domain_perm_ops(ctx->data_domain);
	if (!perm_ops || !perm_ops->grant || !perm_ops->ungrant) {
#ifndef CONFIG_IOMMU_KSVA
		pr_err("%s: kernel is built without CONFIG_IOMMU_KSVA; MAPT grants are unavailable\n",
		       URMA_CLIENT_NAME);
#endif
		pr_err("%s: data tdev domain does not support MAPT grants\n",
		       URMA_CLIENT_NAME);
		ret = -EOPNOTSUPP;
		goto err_free_tdev;
	}

	if (tid == UMMU_NO_TID || tid == UMMU_INVALID_TID) {
		pr_err("%s: data tdev returned invalid TID %u\n",
		       URMA_CLIENT_NAME, tid);
		ret = -EOPNOTSUPP;
		goto err_free_tdev;
	}

	get_random_bytes(&ctx->data_token_value,
			 sizeof(ctx->data_token_value));
	if (!ctx->data_token_value)
		ctx->data_token_value = 1;

	ctx->data_tid = tid;
	ctx->data_token_id = tid << UDMA_TID_SHIFT;

	pr_info("%s: Data tdev allocated, tid=%u, token_id=0x%x, token=0x%x\n",
		URMA_CLIENT_NAME, ctx->data_tid, ctx->data_token_id,
		ctx->data_token_value);
	return 0;

err_free_tdev:
	ummu_core_free_tdev(ctx->data_tdev);
	ctx->data_tdev = NULL;
	ctx->data_domain = NULL;
	return ret;
}

static int urma_client_grant_data_iova(struct urma_client_ctx *ctx)
{
	struct ummu_token_info token_info = {
		.input = 0,
		.tokenVal = ctx->data_token_value,
	};
	struct ummu_seg_attr seg_attr = {
		.token = &token_info,
		.e_bit = UMMU_EBIT_OFF,
	};
	int ret;

	if (ctx->data_mapt_granted)
		return 0;

	ret = urma_demo_domain_grant(ctx->data_domain, ctx->data_iova,
				     ctx->data_iova_len, UMMU_DEV_READ,
				     &seg_attr);
	if (ret) {
		pr_err("%s: failed to grant data IOVA 0x%llx len=%u token=0x%x: %d\n",
		       URMA_CLIENT_NAME, (unsigned long long)ctx->data_iova,
		       ctx->data_iova_len, ctx->data_token_value, ret);
		return ret;
	}

	ctx->data_mapt_granted = true;
	pr_info("%s: Data IOVA granted, iova=0x%llx len=%u token=0x%x\n",
		URMA_CLIENT_NAME, (unsigned long long)ctx->data_iova,
		ctx->data_iova_len, ctx->data_token_value);
	return 0;
}

static int urma_client_ungrant_data_iova(struct urma_client_ctx *ctx)
{
	struct ummu_token_info token_info = {
		.input = 0,
		.tokenVal = ctx->data_token_value,
	};
	int ret;

	if (!ctx->data_mapt_granted)
		return 0;

	ret = urma_demo_domain_ungrant(ctx->data_domain, ctx->data_iova,
				       ctx->data_iova_len, &token_info);
	if (ret) {
		pr_err("%s: failed to ungrant data IOVA 0x%llx len=%u token=0x%x: %d\n",
		       URMA_CLIENT_NAME, (unsigned long long)ctx->data_iova,
		       ctx->data_iova_len, ctx->data_token_value, ret);
		return ret;
	}

	ctx->data_mapt_granted = false;
	pr_info("%s: Data IOVA ungranted\n", URMA_CLIENT_NAME);
	return 0;
}

static int urma_client_alloc_data_pages(struct urma_client_ctx *ctx, size_t len)
{
	size_t remaining = len;
	u32 crc = (u32)~0U;
	int i;

	for (i = 0; i < URMA_CLIENT_DATA_PAGE_COUNT; i++) {
		unsigned int page_len = min_t(size_t, remaining, PAGE_SIZE);
		void *page_buf;

		ctx->data_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!ctx->data_pages[i])
			return -ENOMEM;

		page_buf = page_address(ctx->data_pages[i]);
		if (!page_buf) {
			pr_err("%s: data page %d has no kernel address\n",
			       URMA_CLIENT_NAME, i);
			return -ENOMEM;
		}

		memset(page_buf, URMA_DEMO_MAGIC_PATTERN, page_len);
		crc = crc32_le(crc, page_buf, page_len);
		remaining -= page_len;

		pr_info("%s: Data page %d pfn=%lu len=%u\n",
			URMA_CLIENT_NAME, i, page_to_pfn(ctx->data_pages[i]),
			page_len);
	}

	ctx->data_crc32 = crc ^ (u32)~0U;
	return 0;
}

static void urma_client_unmap_data_sgt(struct urma_client_ctx *ctx)
{
	if (!ctx->data_dma_mapped)
		return;

	dma_unmap_sgtable(ctx->data_tdev, &ctx->data_sgt, DMA_TO_DEVICE, 0);
	ctx->data_dma_mapped = false;
	ctx->data_iova = 0;
	ctx->data_iova_len = 0;
}

static void urma_client_free_data_pages(struct urma_client_ctx *ctx)
{
	int i;

	for (i = 0; i < URMA_CLIENT_DATA_PAGE_COUNT; i++) {
		if (!ctx->data_pages[i])
			continue;

		__free_page(ctx->data_pages[i]);
		ctx->data_pages[i] = NULL;
	}
}

static void urma_client_release_data_window(struct urma_client_ctx *ctx)
{
	if (urma_client_ungrant_data_iova(ctx)) {
		pr_err("%s: keeping data mapping because MAPT ungrant failed\n",
		       URMA_CLIENT_NAME);
		return;
	}

	urma_client_unmap_data_sgt(ctx);
	urma_client_free_data_pages(ctx);

	if (ctx->data_tdev) {
		ummu_core_free_tdev(ctx->data_tdev);
		ctx->data_tdev = NULL;
		ctx->data_domain = NULL;
		ctx->data_tid = 0;
		ctx->data_token_id = 0;
		ctx->data_token_value = 0;
	}
}

static int urma_client_map_data_sgt(struct urma_client_ctx *ctx, size_t len)
{
	size_t remaining = len;
	int ret;
	int i;

	if (!ctx->data_tdev)
		return -ENODEV;
	if (len > URMA_CLIENT_DATA_PAGE_COUNT * PAGE_SIZE)
		return -EINVAL;

	sg_init_table(ctx->data_sgl, URMA_CLIENT_DATA_PAGE_COUNT);
	for (i = 0; i < URMA_CLIENT_DATA_PAGE_COUNT; i++) {
		unsigned int page_len = min_t(size_t, remaining, PAGE_SIZE);

		if (!ctx->data_pages[i])
			return -EINVAL;

		sg_set_page(&ctx->data_sgl[i], ctx->data_pages[i], page_len, 0);
		remaining -= page_len;
	}

	ctx->data_sgt.sgl = ctx->data_sgl;
	ctx->data_sgt.orig_nents = URMA_CLIENT_DATA_PAGE_COUNT;
	ctx->data_sgt.nents = URMA_CLIENT_DATA_PAGE_COUNT;

	ret = dma_map_sgtable(ctx->data_tdev, &ctx->data_sgt,
			      DMA_TO_DEVICE, 0);
	if (ret) {
		pr_err("%s: failed to DMA map data sgtable: %d\n",
		       URMA_CLIENT_NAME, ret);
		return ret;
	}
	ctx->data_dma_mapped = true;

	if (ctx->data_sgt.nents != 1 || sg_dma_len(ctx->data_sgt.sgl) != len) {
		pr_err("%s: DMA sgtable did not map to one %zu-byte segment (nents=%u, len=%u)\n",
		       URMA_CLIENT_NAME, len, ctx->data_sgt.nents,
		       sg_dma_len(ctx->data_sgt.sgl));
		urma_client_unmap_data_sgt(ctx);
		return -ERANGE;
	}

	ctx->data_iova = sg_dma_address(ctx->data_sgt.sgl);
	ctx->data_iova_len = sg_dma_len(ctx->data_sgt.sgl);

	pr_info("%s: Data sgtable DMA mapped by tdev, iova=%pad, len=%u\n",
		URMA_CLIENT_NAME, &ctx->data_iova, ctx->data_iova_len);

	ret = urma_client_grant_data_iova(ctx);
	if (ret)
		urma_client_unmap_data_sgt(ctx);

	return ret;
}

/*
 * Poll JFC for completions with timeout
 */
static int urma_client_poll_jfc(struct ubcore_jfc *jfc, struct ubcore_cr *cr,
				int timeout_ms)
{
	int ret;
	int elapsed = 0;

	while (elapsed < timeout_ms) {
		ret = ubcore_poll_jfc(jfc, 1, cr);
		if (ret > 0)
			return 0;
		if (ret < 0)
			return ret;

		usleep_range(URMA_DEMO_POLL_INTERVAL_US,
			     URMA_DEMO_POLL_INTERVAL_US + 50);
		elapsed += URMA_DEMO_POLL_INTERVAL_US / 1000;
	}

	return -ETIMEDOUT;
}

/*
 * Select EID index for this device
 */
static int urma_client_select_eid_index(struct ubcore_device *ub_dev,
					u32 *eid_index)
{
	u8 eid_raw[URMA_DEMO_EID_SIZE];
	u32 i;
	int ret;

	if (!ub_dev || !eid_index)
		return -EINVAL;

	if (strlen(local_eid) > 0) {
		ret = urma_demo_parse_eid(local_eid, eid_raw);
		if (ret) {
			pr_err("%s: invalid local_eid: %s\n", URMA_CLIENT_NAME,
			       local_eid);
			return ret;
		}

		for (i = 0; i < ub_dev->eid_table.eid_cnt; i++) {
			if (!ub_dev->eid_table.eid_entries[i].valid)
				continue;
			if (memcmp(ub_dev->eid_table.eid_entries[i].eid.raw,
				   eid_raw, URMA_DEMO_EID_SIZE) == 0) {
				*eid_index = i;
				return 0;
			}
		}

		pr_err("%s: local_eid not found in device EID table\n",
		       URMA_CLIENT_NAME);
		return -ENODEV;
	}

	for (i = 0; i < ub_dev->eid_table.eid_cnt; i++) {
		if (ub_dev->eid_table.eid_entries[i].valid) {
			*eid_index = i;
			return 0;
		}
	}

	pr_err("%s: device %s has no valid EIDs\n", URMA_CLIENT_NAME,
	       ub_dev->dev_name);
	return -ENODEV;
}

static u32 urma_client_effective_server_jetty(void)
{
	return server_jetty;
}

static u32 urma_client_effective_client_jetty(void)
{
	return client_jetty;
}

static void urma_client_init_tjetty_cfg(struct ubcore_tjetty_cfg *cfg,
					const u8 *eid, u32 jetty_id,
					u32 eid_index)
{
	memset(cfg, 0, sizeof(*cfg));
	memcpy(cfg->id.eid.raw, eid, URMA_DEMO_EID_SIZE);
	cfg->id.id = jetty_id;
	cfg->trans_mode = UBCORE_TP_RM;
	cfg->eid_index = eid_index;
	cfg->type = UBCORE_JETTY;
	cfg->flag.bs.token_policy = UBCORE_TOKEN_NONE;
}

/*
 * Create URMA resources (JFC, JFR, Jetty)
 */
static int urma_client_create_resources(struct urma_client_ctx *ctx)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfr_cfg jfr_cfg = { 0 };
	struct ubcore_jetty_cfg jetty_cfg = { 0 };
	struct ubcore_seg_cfg seg_cfg = { 0 };
	int ret;
	size_t data_len;
	size_t msg_buf_len;
	char eid_str[64];

	/* Create JFC (completion queue) */
	jfc_cfg.depth = URMA_DEMO_JFC_DEPTH;
	jfc_cfg.flag.bs.lock_free = 0;

	ctx->jfc = ubcore_create_jfc(ctx->ub_dev, &jfc_cfg, NULL, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfc)) {
		pr_err("%s: failed to create JFC\n", URMA_CLIENT_NAME);
		return urma_demo_ptr_err_or(ctx->jfc, -ENOMEM);
	}
	pr_info("%s: JFC created, id=%u\n", URMA_CLIENT_NAME, ctx->jfc->id);

	/* Create JFR (receive queue) for RM mode */
	jfr_cfg.depth = URMA_DEMO_JFR_DEPTH;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	jfr_cfg.trans_mode = UBCORE_TP_RM;
	jfr_cfg.eid_index = ctx->eid_index;
	jfr_cfg.max_sge = 1;
	jfr_cfg.min_rnr_timer = 12;
	jfr_cfg.jfc = ctx->jfc;

	ctx->jfr = ubcore_create_jfr(ctx->ub_dev, &jfr_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfr)) {
		pr_err("%s: failed to create JFR\n", URMA_CLIENT_NAME);
		ret = urma_demo_ptr_err_or(ctx->jfr, -ENOMEM);
		goto err_delete_jfc;
	}
	pr_info("%s: JFR created, id=%u\n", URMA_CLIENT_NAME,
		ctx->jfr->jfr_id.id);

	/* Create Jetty for RM mode */
	jetty_cfg.jfs_depth = URMA_DEMO_JFS_DEPTH;
	jetty_cfg.jfr_depth = URMA_DEMO_JFR_DEPTH;
	jetty_cfg.flag.bs.share_jfr = 1;
	jetty_cfg.trans_mode = UBCORE_TP_RM;
	jetty_cfg.eid_index = ctx->eid_index;
	jetty_cfg.id = urma_client_effective_client_jetty();
	if (jetty_cfg.id == 0) {
		pr_err("%s: client_jetty must be non-zero\n", URMA_CLIENT_NAME);
		ret = -EINVAL;
		goto err_delete_jfr;
	}
	jetty_cfg.max_send_sge = 1;
	jetty_cfg.max_recv_sge = 1;
	jetty_cfg.rnr_retry = 7;
	jetty_cfg.err_timeout = 14;
	jetty_cfg.send_jfc = ctx->jfc;
	jetty_cfg.recv_jfc = ctx->jfc;
	jetty_cfg.jfr = ctx->jfr;

	ctx->jetty = ubcore_create_jetty(ctx->ub_dev, &jetty_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jetty)) {
		pr_err("%s: failed to create jetty\n", URMA_CLIENT_NAME);
		ret = urma_demo_ptr_err_or(ctx->jetty, -ENOMEM);
		goto err_delete_jfr;
	}

	urma_demo_format_eid(ctx->jetty->jetty_id.eid.raw, eid_str,
			     sizeof(eid_str));
	pr_info("%s: Jetty created, id=%u, eid=%s\n", URMA_CLIENT_NAME,
		ctx->jetty->jetty_id.id, eid_str);

	data_len = PAGE_ALIGN(URMA_DEMO_CLIENT_BUF_SIZE);
	msg_buf_len = ALIGN(URMA_DEMO_MSG_BUF_SIZE, 4096);

	ret = urma_client_alloc_data_tdev(ctx);
	if (ret)
		goto err_delete_jetty;

	ret = urma_client_alloc_data_pages(ctx, data_len);
	if (ret)
		goto err_release_data_window;

	ret = urma_client_map_data_sgt(ctx, data_len);
	if (ret)
		goto err_release_data_window;

	seg_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	seg_cfg.flag.bs.access = UBCORE_ACCESS_READ | UBCORE_ACCESS_WRITE;
	seg_cfg.eid_index = ctx->eid_index;

	/* Allocate and register send buffer */
	ctx->send_buf = kzalloc(msg_buf_len, GFP_KERNEL);
	if (!ctx->send_buf) {
		ret = -ENOMEM;
		goto err_release_data_window;
	}
	if (!IS_ALIGNED((unsigned long)ctx->send_buf, 4096)) {
		pr_err("%s: send buffer is not 4KB aligned\n",
		       URMA_CLIENT_NAME);
		ret = -EINVAL;
		goto err_free_send_buf;
	}

	seg_cfg.va = (u64)ctx->send_buf;
	seg_cfg.len = msg_buf_len;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->send_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->send_seg)) {
		pr_err("%s: failed to register send segment\n",
		       URMA_CLIENT_NAME);
		ret = urma_demo_ptr_err_or(ctx->send_seg, -ENOMEM);
		goto err_free_send_buf;
	}

	/* Allocate and register receive buffer */
	ctx->recv_buf = kzalloc(msg_buf_len, GFP_KERNEL);
	if (!ctx->recv_buf) {
		ret = -ENOMEM;
		goto err_unreg_send_seg;
	}
	if (!IS_ALIGNED((unsigned long)ctx->recv_buf, 4096)) {
		pr_err("%s: recv buffer is not 4KB aligned\n",
		       URMA_CLIENT_NAME);
		ret = -EINVAL;
		goto err_free_recv_buf;
	}

	seg_cfg.va = (u64)ctx->recv_buf;
	seg_cfg.len = msg_buf_len;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->recv_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->recv_seg)) {
		pr_err("%s: failed to register recv segment\n",
		       URMA_CLIENT_NAME);
		ret = urma_demo_ptr_err_or(ctx->recv_seg, -ENOMEM);
		goto err_free_recv_buf;
	}

	/* Setup SGEs */
	ctx->send_sge.addr = (u64)ctx->send_buf;
	ctx->send_sge.len = sizeof(struct urma_demo_seg_info_msg);
	ctx->send_sge.tseg = ctx->send_seg;

	ctx->recv_sge.addr = (u64)ctx->recv_buf;
	ctx->recv_sge.len = sizeof(struct urma_demo_reply_msg);
	ctx->recv_sge.tseg = ctx->recv_seg;

	ctx->initialized = true;
	return 0;

err_free_recv_buf:
	kfree(ctx->recv_buf);
err_unreg_send_seg:
	ubcore_unregister_seg(ctx->send_seg);
err_free_send_buf:
	kfree(ctx->send_buf);
err_release_data_window:
	urma_client_release_data_window(ctx);
err_delete_jetty:
	ubcore_delete_jetty(ctx->jetty);
err_delete_jfr:
	ubcore_delete_jfr(ctx->jfr);
err_delete_jfc:
	ubcore_delete_jfc(ctx->jfc);
	return ret;
}

/*
 * Connect to server by importing server's jetty
 */
static int urma_client_connect(struct urma_client_ctx *ctx)
{
	struct ubcore_tjetty_cfg tjetty_cfg;
	char eid_str[64];
	int ret;

	if (strlen(server_eid) == 0) {
		pr_err("%s: server_eid must be specified\n", URMA_CLIENT_NAME);
		return -EINVAL;
	}
	/* Parse server EID */
	if (urma_demo_parse_eid(server_eid, ctx->server_eid_raw) != 0) {
		pr_err("%s: invalid server_eid format: %s\n", URMA_CLIENT_NAME,
		       server_eid);
		return -EINVAL;
	}

	urma_demo_format_eid(ctx->server_eid_raw, eid_str, sizeof(eid_str));
	{
		u32 remote_jetty = urma_client_effective_server_jetty();

		if (remote_jetty == 0) {
			pr_err("%s: server_jetty must be non-zero\n",
			       URMA_CLIENT_NAME);
			return -EINVAL;
		}

		pr_info("%s: Connecting to server EID=%s, jetty_id=%u\n",
			URMA_CLIENT_NAME, eid_str, remote_jetty);
	}

	/* Configure target jetty for import */
	urma_client_init_tjetty_cfg(&tjetty_cfg, ctx->server_eid_raw,
				    urma_client_effective_server_jetty(),
				    ctx->eid_index);

	/* Import server's jetty (for RM mode, this creates connection) */
	ctx->tjetty = ubcore_import_jetty(ctx->ub_dev, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->tjetty)) {
		ret = urma_demo_ptr_err_or(ctx->tjetty, -ENODEV);
		pr_err("%s: failed to import server jetty: %d\n",
		       URMA_CLIENT_NAME, ret);
		ctx->tjetty = NULL;
		return ret;
	}

	ctx->connected = true;
	pr_info("%s: Connected to server successfully\n", URMA_CLIENT_NAME);
	return 0;
}

/*
 * Post receive buffer for reply
 */
static int urma_client_post_recv(struct urma_client_ctx *ctx)
{
	struct ubcore_jfr_wr recv_wr = { 0 };
	struct ubcore_jfr_wr *bad_wr = NULL;
	int ret;

	recv_wr.src.sge = &ctx->recv_sge;
	recv_wr.src.num_sge = 1;
	recv_wr.user_ctx = (u64)ctx;

	ret = ubcore_post_jetty_recv_wr(ctx->jetty, &recv_wr, &bad_wr);
	if (ret) {
		pr_err("%s: failed to post receive WR: %d\n", URMA_CLIENT_NAME,
		       ret);
		return ret;
	}

	return 0;
}

/*
 * Send segment info message to server
 */
static int urma_client_send_seg_info(struct urma_client_ctx *ctx)
{
	struct urma_demo_seg_info_msg *msg;
	struct ubcore_jfs_wr send_wr = { 0 };
	struct ubcore_jfs_wr *bad_wr = NULL;
	struct ubcore_cr cr = { 0 };
	int ret;

	if (!ctx->tjetty) {
		pr_err("%s: cannot send segment info: server jetty is not connected\n",
		       URMA_CLIENT_NAME);
		return -ENOTCONN;
	}

	/* Prepare message */
	msg = (struct urma_demo_seg_info_msg *)ctx->send_buf;
	memset(msg, 0, sizeof(*msg));

	msg->msg_type = URMA_DEMO_MSG_TYPE_SEG_INFO;
	msg->seg_va = ctx->data_iova;
	msg->seg_len = ctx->data_iova_len;
	msg->token = ctx->data_token_value;
	msg->token_id = ctx->data_token_id;
	memcpy(msg->src_eid, ctx->jetty->jetty_id.eid.raw, URMA_DEMO_EID_SIZE);
	msg->src_jetty_id = ctx->jetty->jetty_id.id;

	pr_info("%s: Sending seg info: iova=0x%llx, len=%u, token_id=0x%x, token=0x%x, jetty_id=%u\n",
		URMA_CLIENT_NAME, msg->seg_va, msg->seg_len,
		msg->token_id, msg->token, msg->src_jetty_id);

	/* Prepare send WR */
	send_wr.opcode = UBCORE_OPC_SEND;
	send_wr.flag.bs.complete_enable = 1;
	send_wr.user_ctx = (u64)ctx;
	send_wr.tjetty = ctx->tjetty;
	send_wr.send.src.sge = &ctx->send_sge;
	send_wr.send.src.num_sge = 1;

	/* Post send */
	ret = ubcore_post_jetty_send_wr(ctx->jetty, &send_wr, &bad_wr);
	if (ret) {
		pr_err("%s: failed to post send WR: %d\n", URMA_CLIENT_NAME,
		       ret);
		return ret;
	}

	/* Wait for send completion */
	ret = urma_client_poll_jfc(ctx->jfc, &cr, URMA_DEMO_POLL_TIMEOUT_MS);
	if (ret) {
		pr_err("%s: send completion timeout\n", URMA_CLIENT_NAME);
		return ret;
	}

	if (cr.status != UBCORE_CR_SUCCESS) {
		pr_err("%s: send failed with status %d\n", URMA_CLIENT_NAME,
		       cr.status);
		return -EIO;
	}

	pr_info("%s: Send completed successfully\n", URMA_CLIENT_NAME);
	return 0;
}

/*
 * Wait for reply from server
 */
static int urma_client_wait_reply(struct urma_client_ctx *ctx)
{
	struct urma_demo_reply_msg *reply;
	struct ubcore_cr cr = { 0 };
	u32 expected_crc32;
	int ret;

	pr_info("%s: Waiting for reply from server...\n", URMA_CLIENT_NAME);

	/* Poll for receive completion */
	ret = urma_client_poll_jfc(ctx->jfc, &cr,
				   URMA_DEMO_POLL_TIMEOUT_MS * 2);
	if (ret) {
		pr_err("%s: reply timeout\n", URMA_CLIENT_NAME);
		return ret;
	}

	if (cr.status != UBCORE_CR_SUCCESS) {
		pr_err("%s: receive failed with status %d\n", URMA_CLIENT_NAME,
		       cr.status);
		return -EIO;
	}

	/* Parse reply */
	reply = (struct urma_demo_reply_msg *)ctx->recv_buf;

	if (reply->msg_type != URMA_DEMO_MSG_TYPE_REPLY) {
		pr_err("%s: unexpected message type: %u\n", URMA_CLIENT_NAME,
		       reply->msg_type);
		return -EINVAL;
	}

	if (reply->status == URMA_DEMO_STATUS_SUCCESS) {
		pr_info("%s: Server successfully read %u bytes via RDMA\n",
			URMA_CLIENT_NAME, reply->bytes_read);
		pr_info("%s: Server CRC32: 0x%08x\n", URMA_CLIENT_NAME,
			reply->data_crc32);
		pr_info("%s: Sample data: %02x %02x %02x %02x %02x %02x %02x %02x\n",
			URMA_CLIENT_NAME, reply->sample_data[0],
			reply->sample_data[1], reply->sample_data[2],
			reply->sample_data[3], reply->sample_data[4],
			reply->sample_data[5], reply->sample_data[6],
			reply->sample_data[7]);

		if (reply->bytes_read != URMA_DEMO_CLIENT_BUF_SIZE) {
			pr_err("%s: Data verification FAILED - expected %u bytes, got %u\n",
			       URMA_CLIENT_NAME, URMA_DEMO_CLIENT_BUF_SIZE,
			       reply->bytes_read);
			return -EIO;
		}

		expected_crc32 = ctx->data_crc32;
		if (reply->data_crc32 != expected_crc32) {
			pr_err("%s: Data verification FAILED - expected crc32=0x%08x, got 0x%08x\n",
			       URMA_CLIENT_NAME, expected_crc32,
			       reply->data_crc32);
			return -EIO;
		}

		pr_info("%s: Data CRC32 verification PASSED!\n",
			URMA_CLIENT_NAME);
	} else {
		pr_err("%s: Server reported error status: %u\n",
		       URMA_CLIENT_NAME, reply->status);
		return -EIO;
	}

	return 0;
}

/*
 * Run the client test
 */
static int urma_client_run_test(struct urma_client_ctx *ctx)
{
	int ret;

	/* Connect to server */
	ret = urma_client_connect(ctx);
	if (ret)
		return ret;

	/* Post receive buffer for reply */
	ret = urma_client_post_recv(ctx);
	if (ret)
		goto err_disconnect;

	/* Send segment info to server */
	ret = urma_client_send_seg_info(ctx);
	if (ret)
		goto err_disconnect;

	/* Wait for reply */
	ret = urma_client_wait_reply(ctx);
	if (ret)
		goto err_disconnect;

	urma_client_release_data_window(ctx);
	pr_info("%s: Test completed successfully!\n", URMA_CLIENT_NAME);
	return 0;

err_disconnect:
	if (ctx->tjetty) {
		ubcore_unimport_jetty(ctx->tjetty);
		ctx->tjetty = NULL;
	}
	ctx->connected = false;
	return ret;
}

/*
 * ubcore client add device callback
 */
static int urma_client_add_dev(struct ubcore_device *ub_dev)
{
	struct urma_client_ctx *ctx = &g_client_ctx;
	int ret;

	/* Check if we're looking for a specific device */
	if (strlen(device_name) > 0 &&
	    strcmp(device_name, ub_dev->dev_name) != 0) {
		pr_info("%s: Skipping device %s (waiting for %s)\n",
			URMA_CLIENT_NAME, ub_dev->dev_name, device_name);
		return -ENODEV;
	}

	/* Check transport type */
	if (ub_dev->transport_type != UBCORE_TRANSPORT_UB) {
		pr_info("%s: Skipping non-UB device %s\n", URMA_CLIENT_NAME,
			ub_dev->dev_name);
		return -ENODEV;
	}

	/* Select EID index */
	ret = urma_client_select_eid_index(ub_dev, &ctx->eid_index);
	if (ret)
		return ret;
	pr_info("%s: Selected EID index=%u\n", URMA_CLIENT_NAME,
		ctx->eid_index);

	pr_info("%s: Using device %s\n", URMA_CLIENT_NAME, ub_dev->dev_name);
	ctx->ub_dev = ub_dev;

	/* Create URMA resources */
	ret = urma_client_create_resources(ctx);
	if (ret) {
		pr_err("%s: failed to create resources: %d\n", URMA_CLIENT_NAME,
		       ret);
		ctx->ub_dev = NULL;
		return ret;
	}

	/* Run test if server parameters are provided */
	if (strlen(server_eid) > 0) {
		ret = urma_client_run_test(ctx);
		if (ret) {
			pr_err("%s: test failed: %d\n", URMA_CLIENT_NAME, ret);
			/* Don't return error - resources are created */
		}
	} else {
		char eid_str[64];
		urma_demo_format_eid(ctx->jetty->jetty_id.eid.raw, eid_str,
				     sizeof(eid_str));
		pr_info("%s: Client ready. EID=%s, jetty_id=%u\n",
			URMA_CLIENT_NAME, eid_str, ctx->jetty->jetty_id.id);
		pr_info("%s: Load module with server_eid=<eid> server_jetty=<id> to run test\n",
			URMA_CLIENT_NAME);
	}

	return 0;
}

/*
 * ubcore client remove device callback
 */
static void urma_client_remove_dev(struct ubcore_device *ub_dev,
				   void *client_data)
{
	struct urma_client_ctx *ctx = &g_client_ctx;

	if (ctx->ub_dev != ub_dev)
		return;

	pr_info("%s: Removing device %s\n", URMA_CLIENT_NAME, ub_dev->dev_name);

	/* Disconnect */
	if (ctx->tjetty) {
		ubcore_unimport_jetty(ctx->tjetty);
		ctx->tjetty = NULL;
	}

	/* Cleanup resources */
	if (ctx->recv_seg)
		ubcore_unregister_seg(ctx->recv_seg);
	if (ctx->recv_buf)
		kfree(ctx->recv_buf);
	if (ctx->send_seg)
		ubcore_unregister_seg(ctx->send_seg);
	if (ctx->send_buf)
		kfree(ctx->send_buf);
	urma_client_release_data_window(ctx);
	if (ctx->jetty)
		ubcore_delete_jetty(ctx->jetty);
	if (ctx->jfr)
		ubcore_delete_jfr(ctx->jfr);
	if (ctx->jfc)
		ubcore_delete_jfc(ctx->jfc);

	ctx->initialized = false;
	ctx->connected = false;
	ctx->ub_dev = NULL;
}

static struct ubcore_client urma_client = {
	.client_name = URMA_CLIENT_NAME,
	.add = urma_client_add_dev,
	.remove = urma_client_remove_dev,
};

static int __init urma_client_init(void)
{
	int ret;

	pr_info("%s: Loading URMA client demo module\n", URMA_CLIENT_NAME);

	memset(&g_client_ctx, 0, sizeof(g_client_ctx));
	g_client_ctx.ub_client = urma_client;

	ret = ubcore_register_client(&g_client_ctx.ub_client);
	if (ret) {
		pr_err("%s: failed to register ubcore client: %d\n",
		       URMA_CLIENT_NAME, ret);
		return ret;
	}

	pr_info("%s: Module loaded successfully\n", URMA_CLIENT_NAME);
	return 0;
}

static void __exit urma_client_exit(void)
{
	pr_info("%s: Unloading URMA client demo module\n", URMA_CLIENT_NAME);

	ubcore_unregister_client(&g_client_ctx.ub_client);

	pr_info("%s: Module unloaded\n", URMA_CLIENT_NAME);
}

module_init(urma_client_init);
module_exit(urma_client_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("URMA Demo");
MODULE_DESCRIPTION(
	"URMA Kernel Client Demo - sends segment info and receives RDMA read reply");
MODULE_VERSION("1.0");
