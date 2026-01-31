// SPDX-License-Identifier: GPL-2.0
/*
 * URMA Kernel Module Demo - Server
 *
 * This module demonstrates URMA kernel API usage as a server:
 * 1. Receives segment information from client
 * 2. Imports client's segment and performs RDMA read
 * 3. Sends reply with read data sample
 *
 * Copyright (c) 2024
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>

#include "urma_demo_common.h"

#define URMA_SERVER_NAME "urma_demo_server"

/* Module parameters - can be set at runtime via debugfs */
static char *device_name = "";
module_param(device_name, charp, 0444);
MODULE_PARM_DESC(device_name,
		 "URMA device name (optional, uses first available if not set)");

static char *local_eid = "";
module_param(local_eid, charp, 0444);
MODULE_PARM_DESC(
	local_eid,
	"Local EID to select EID index (optional, format: xx:xx:...:xx)");

/* Optional parameters for early client jetty import */
static char *client_eid = "";
module_param(client_eid, charp, 0444);
MODULE_PARM_DESC(
	client_eid,
	"Client EID for early jetty import (optional, format: xx:xx:...:xx)");

static uint client_jetty_id;
module_param(client_jetty_id, uint, 0444);
MODULE_PARM_DESC(client_jetty_id,
		 "Client jetty ID for early jetty import (optional)");

/* Server context structure */
struct urma_server_ctx {
	/* Device and client registration */
	struct ubcore_device *ub_dev;
	struct ubcore_client ub_client;

	/* Resources */
	struct ubcore_jfc *jfc;
	struct ubcore_jfr *jfr;
	struct ubcore_jetty *jetty;

	/* Buffers */
	void *recv_buf; /* Receive buffer for client message */
	void *send_buf; /* Send buffer for reply */
	void *read_buf; /* Buffer for RDMA read data */
	struct ubcore_target_seg *recv_seg;
	struct ubcore_target_seg *send_seg;
	struct ubcore_target_seg *read_seg;

	/* Imported client segment for RDMA read */
	struct ubcore_target_seg *client_seg;
	struct ubcore_tjetty *client_tjetty;
	bool jetty_imported_early; /* True if client jetty imported via module params */

	/* SGEs */
	struct ubcore_sge recv_sge;
	struct ubcore_sge send_sge;
	struct ubcore_sge read_local_sge; /* Local destination for RDMA read */
	struct ubcore_sge read_remote_sge; /* Remote source for RDMA read */

	/* State */
	bool initialized;
	bool waiting;
	u32 eid_index;

	/* Debugfs */
	struct dentry *debugfs_dir;
};

static struct urma_server_ctx g_server_ctx;

/*
 * Poll JFC for completions with timeout
 */
static int urma_server_poll_jfc(struct ubcore_jfc *jfc, struct ubcore_cr *cr,
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
static int urma_server_select_eid_index(struct ubcore_device *ub_dev,
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
			pr_err("%s: invalid local_eid: %s\n", URMA_SERVER_NAME,
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
		       URMA_SERVER_NAME);
		return -ENODEV;
	}

	for (i = 0; i < ub_dev->eid_table.eid_cnt; i++) {
		if (ub_dev->eid_table.eid_entries[i].valid) {
			*eid_index = i;
			return 0;
		}
	}

	pr_err("%s: device %s has no valid EIDs\n", URMA_SERVER_NAME,
	       ub_dev->dev_name);
	return -ENODEV;
}

/*
 * Create URMA resources (JFC, JFR, Jetty)
 */
static int urma_server_create_resources(struct urma_server_ctx *ctx)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfr_cfg jfr_cfg = { 0 };
	struct ubcore_jetty_cfg jetty_cfg = { 0 };
	struct ubcore_seg_cfg seg_cfg = { 0 };
	int ret;
	size_t msg_buf_len;
	size_t read_buf_len;
	char eid_str[64];

	/* Create JFC (completion queue) */
	jfc_cfg.depth = URMA_DEMO_JFC_DEPTH;
	jfc_cfg.flag.bs.lock_free = 0;

	ctx->jfc = ubcore_create_jfc(ctx->ub_dev, &jfc_cfg, NULL, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfc)) {
		pr_err("%s: failed to create JFC\n", URMA_SERVER_NAME);
		return PTR_ERR(ctx->jfc);
	}
	pr_info("%s: JFC created, id=%u\n", URMA_SERVER_NAME, ctx->jfc->id);

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
		pr_err("%s: failed to create JFR\n", URMA_SERVER_NAME);
		ret = PTR_ERR(ctx->jfr);
		goto err_delete_jfc;
	}
	pr_info("%s: JFR created, id=%u\n", URMA_SERVER_NAME,
		ctx->jfr->jfr_id.id);

	/* Create Jetty for RM mode */
	jetty_cfg.jfs_depth = URMA_DEMO_JFS_DEPTH;
	jetty_cfg.jfr_depth = URMA_DEMO_JFR_DEPTH;
	jetty_cfg.flag.bs.share_jfr = 1;
	jetty_cfg.trans_mode = UBCORE_TP_RM;
	jetty_cfg.eid_index = ctx->eid_index;
	jetty_cfg.max_send_sge = 2; /* Need 2 for RDMA read (src/dst) */
	jetty_cfg.max_recv_sge = 1;
	jetty_cfg.rnr_retry = 7;
	jetty_cfg.err_timeout = 14;
	jetty_cfg.send_jfc = ctx->jfc;
	jetty_cfg.recv_jfc = ctx->jfc;
	jetty_cfg.jfr = ctx->jfr;

	ctx->jetty = ubcore_create_jetty(ctx->ub_dev, &jetty_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jetty)) {
		pr_err("%s: failed to create jetty\n", URMA_SERVER_NAME);
		ret = PTR_ERR(ctx->jetty);
		goto err_delete_jfr;
	}

	urma_demo_format_eid(ctx->jetty->jetty_id.eid.raw, eid_str,
			     sizeof(eid_str));
	pr_info("%s: Jetty created, id=%u, eid=%s\n", URMA_SERVER_NAME,
		ctx->jetty->jetty_id.id, eid_str);

	msg_buf_len = ALIGN(URMA_DEMO_MSG_BUF_SIZE, 4096);
	read_buf_len = ALIGN(URMA_DEMO_CLIENT_BUF_SIZE, 4096);

	/* Allocate and register receive buffer */
	ctx->recv_buf = kzalloc(msg_buf_len, GFP_KERNEL);
	if (!ctx->recv_buf) {
		ret = -ENOMEM;
		goto err_delete_jetty;
	}
	if (!IS_ALIGNED((unsigned long)ctx->recv_buf, 4096)) {
		pr_err("%s: recv buffer is not 4KB aligned\n",
		       URMA_SERVER_NAME);
		ret = -EINVAL;
		goto err_free_recv_buf;
	}

	seg_cfg.va = (u64)ctx->recv_buf;
	seg_cfg.len = msg_buf_len;
	seg_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	seg_cfg.flag.bs.access = UBCORE_ACCESS_LOCAL_ONLY | UBCORE_ACCESS_READ |
				 UBCORE_ACCESS_WRITE;
	seg_cfg.eid_index = ctx->eid_index;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->recv_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->recv_seg)) {
		pr_err("%s: failed to register recv segment\n",
		       URMA_SERVER_NAME);
		ret = PTR_ERR(ctx->recv_seg);
		goto err_free_recv_buf;
	}

	/* Allocate and register send buffer */
	ctx->send_buf = kzalloc(msg_buf_len, GFP_KERNEL);
	if (!ctx->send_buf) {
		ret = -ENOMEM;
		goto err_unreg_recv_seg;
	}
	if (!IS_ALIGNED((unsigned long)ctx->send_buf, 4096)) {
		pr_err("%s: send buffer is not 4KB aligned\n",
		       URMA_SERVER_NAME);
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
		       URMA_SERVER_NAME);
		ret = PTR_ERR(ctx->send_seg);
		goto err_free_send_buf;
	}

	/* Allocate and register RDMA read destination buffer */
	ctx->read_buf = kzalloc(read_buf_len, GFP_KERNEL);
	if (!ctx->read_buf) {
		ret = -ENOMEM;
		goto err_unreg_send_seg;
	}
	if (!IS_ALIGNED((unsigned long)ctx->read_buf, 4096)) {
		pr_err("%s: read buffer is not 4KB aligned\n",
		       URMA_SERVER_NAME);
		ret = -EINVAL;
		goto err_free_read_buf;
	}

	seg_cfg.va = (u64)ctx->read_buf;
	seg_cfg.len = read_buf_len;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->read_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->read_seg)) {
		pr_err("%s: failed to register read segment\n",
		       URMA_SERVER_NAME);
		ret = PTR_ERR(ctx->read_seg);
		goto err_free_read_buf;
	}

	/* Setup SGEs */
	ctx->recv_sge.addr = (u64)ctx->recv_buf;
	ctx->recv_sge.len = sizeof(struct urma_demo_seg_info_msg);
	ctx->recv_sge.tseg = ctx->recv_seg;

	ctx->send_sge.addr = (u64)ctx->send_buf;
	ctx->send_sge.len = sizeof(struct urma_demo_reply_msg);
	ctx->send_sge.tseg = ctx->send_seg;

	ctx->read_local_sge.addr = (u64)ctx->read_buf;
	ctx->read_local_sge.len = URMA_DEMO_CLIENT_BUF_SIZE;
	ctx->read_local_sge.tseg = ctx->read_seg;

	ctx->initialized = true;
	return 0;

err_free_read_buf:
	kfree(ctx->read_buf);
err_unreg_send_seg:
	ubcore_unregister_seg(ctx->send_seg);
err_free_send_buf:
	kfree(ctx->send_buf);
err_unreg_recv_seg:
	ubcore_unregister_seg(ctx->recv_seg);
err_free_recv_buf:
	kfree(ctx->recv_buf);
err_delete_jetty:
	ubcore_delete_jetty(ctx->jetty);
err_delete_jfr:
	ubcore_delete_jfr(ctx->jfr);
err_delete_jfc:
	ubcore_delete_jfc(ctx->jfc);
	return ret;
}

/*
 * Post receive buffer
 */
static int urma_server_post_recv(struct urma_server_ctx *ctx)
{
	struct ubcore_jfr_wr recv_wr = { 0 };
	struct ubcore_jfr_wr *bad_wr = NULL;
	int ret;

	recv_wr.src.sge = &ctx->recv_sge;
	recv_wr.src.num_sge = 1;
	recv_wr.user_ctx = (u64)ctx;

	ret = ubcore_post_jetty_recv_wr(ctx->jetty, &recv_wr, &bad_wr);
	if (ret) {
		pr_err("%s: failed to post receive WR: %d\n", URMA_SERVER_NAME,
		       ret);
		return ret;
	}

	return 0;
}

/*
 * Import client's segment for RDMA read
 */
static int urma_server_import_client_seg(struct urma_server_ctx *ctx,
					 struct urma_demo_seg_info_msg *msg)
{
	struct ubcore_target_seg_cfg seg_cfg = { 0 };
	struct ubcore_tjetty_cfg tjetty_cfg = { 0 };
	char eid_str[64];

	urma_demo_format_eid(msg->src_eid, eid_str, sizeof(eid_str));
	pr_info("%s: Importing client segment: va=0x%llx, len=%u, eid=%s, jetty_id=%u\n",
		URMA_SERVER_NAME, msg->seg_va, msg->seg_len, eid_str,
		msg->src_jetty_id);

	/* Import client's jetty for sending reply (skip if already imported early) */
	if (!ctx->client_tjetty) {
		memcpy(tjetty_cfg.id.eid.raw, msg->src_eid, URMA_DEMO_EID_SIZE);
		tjetty_cfg.id.id = msg->src_jetty_id;
		tjetty_cfg.trans_mode = UBCORE_TP_RM;
		tjetty_cfg.eid_index = ctx->eid_index;
		tjetty_cfg.type = UBCORE_JFR;
		tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;

		ctx->client_tjetty =
			ubcore_import_jetty(ctx->ub_dev, &tjetty_cfg, NULL);
		if (IS_ERR_OR_NULL(ctx->client_tjetty)) {
			pr_err("%s: failed to import client jetty\n",
			       URMA_SERVER_NAME);
			return PTR_ERR(ctx->client_tjetty);
		}
		pr_info("%s: Client jetty imported successfully\n",
			URMA_SERVER_NAME);
	} else {
		pr_info("%s: Using early-imported client jetty\n",
			URMA_SERVER_NAME);
	}

	/* Import client's segment for RDMA read */
	seg_cfg.seg.ubva.va = msg->seg_va;
	memcpy(seg_cfg.seg.ubva.eid.raw, msg->src_eid, URMA_DEMO_EID_SIZE);
	seg_cfg.seg.len = msg->seg_len;
	seg_cfg.seg.token_id = msg->token_id;
	seg_cfg.token_value.token = msg->token;
	seg_cfg.flag.bs.access = UBCORE_ACCESS_READ;

	ctx->client_seg = ubcore_import_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->client_seg)) {
		pr_err("%s: failed to import client segment\n",
		       URMA_SERVER_NAME);
		/* Only unimport jetty if not early-imported */
		if (!ctx->jetty_imported_early && ctx->client_tjetty) {
			ubcore_unimport_jetty(ctx->client_tjetty);
			ctx->client_tjetty = NULL;
		}
		return PTR_ERR(ctx->client_seg);
	}

	/* Setup remote SGE for RDMA read */
	ctx->read_remote_sge.addr = msg->seg_va;
	ctx->read_remote_sge.len = msg->seg_len;
	ctx->read_remote_sge.tseg = ctx->client_seg;

	pr_info("%s: Client segment imported successfully\n", URMA_SERVER_NAME);
	return 0;
}

/*
 * Perform RDMA read from client's memory
 */
static int urma_server_rdma_read(struct urma_server_ctx *ctx)
{
	struct ubcore_jfs_wr read_wr = { 0 };
	struct ubcore_jfs_wr *bad_wr = NULL;
	struct ubcore_cr cr = { 0 };
	int ret;

	pr_info("%s: Performing RDMA read from client memory...\n",
		URMA_SERVER_NAME);

	/* Prepare RDMA READ work request */
	read_wr.opcode = UBCORE_OPC_READ;
	read_wr.flag.bs.complete_enable = 1;
	read_wr.user_ctx = (u64)ctx;
	read_wr.tjetty = ctx->client_tjetty;

	/* Source (remote): client's memory */
	read_wr.rw.src.sge = &ctx->read_remote_sge;
	read_wr.rw.src.num_sge = 1;

	/* Destination (local): our read buffer */
	read_wr.rw.dst.sge = &ctx->read_local_sge;
	read_wr.rw.dst.num_sge = 1;

	/* Post RDMA read */
	ret = ubcore_post_jetty_send_wr(ctx->jetty, &read_wr, &bad_wr);
	if (ret) {
		pr_err("%s: failed to post RDMA read WR: %d\n",
		       URMA_SERVER_NAME, ret);
		return ret;
	}

	/* Wait for read completion */
	ret = urma_server_poll_jfc(ctx->jfc, &cr, URMA_DEMO_POLL_TIMEOUT_MS);
	if (ret) {
		pr_err("%s: RDMA read completion timeout\n", URMA_SERVER_NAME);
		return ret;
	}

	if (cr.status != UBCORE_CR_SUCCESS) {
		pr_err("%s: RDMA read failed with status %d\n",
		       URMA_SERVER_NAME, cr.status);
		return -EIO;
	}

	pr_info("%s: RDMA read completed successfully, read %u bytes\n",
		URMA_SERVER_NAME, cr.completion_len);

	/* Print first few bytes of read data */
	pr_info("%s: Read data: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		URMA_SERVER_NAME, ((u8 *)ctx->read_buf)[0],
		((u8 *)ctx->read_buf)[1], ((u8 *)ctx->read_buf)[2],
		((u8 *)ctx->read_buf)[3], ((u8 *)ctx->read_buf)[4],
		((u8 *)ctx->read_buf)[5], ((u8 *)ctx->read_buf)[6],
		((u8 *)ctx->read_buf)[7]);

	return 0;
}

/*
 * Send reply to client
 */
static int urma_server_send_reply(struct urma_server_ctx *ctx, u32 status,
				  u32 bytes_read)
{
	struct urma_demo_reply_msg *reply;
	struct ubcore_jfs_wr send_wr = { 0 };
	struct ubcore_jfs_wr *bad_wr = NULL;
	struct ubcore_cr cr = { 0 };
	int ret;
	int copy_len;

	/* Prepare reply message */
	reply = (struct urma_demo_reply_msg *)ctx->send_buf;
	memset(reply, 0, sizeof(*reply));

	reply->msg_type = URMA_DEMO_MSG_TYPE_REPLY;
	reply->status = status;
	reply->bytes_read = bytes_read;

	/* Copy sample data if read was successful */
	if (status == URMA_DEMO_STATUS_SUCCESS && bytes_read > 0) {
		copy_len = min_t(int, bytes_read, URMA_DEMO_SAMPLE_DATA_SIZE);
		memcpy(reply->sample_data, ctx->read_buf, copy_len);
	}

	pr_info("%s: Sending reply: status=%u, bytes_read=%u\n",
		URMA_SERVER_NAME, status, bytes_read);

	/* Prepare send WR */
	send_wr.opcode = UBCORE_OPC_SEND;
	send_wr.flag.bs.complete_enable = 1;
	send_wr.user_ctx = (u64)ctx;
	send_wr.tjetty = ctx->client_tjetty;
	send_wr.send.src.sge = &ctx->send_sge;
	send_wr.send.src.num_sge = 1;

	/* Post send */
	ret = ubcore_post_jetty_send_wr(ctx->jetty, &send_wr, &bad_wr);
	if (ret) {
		pr_err("%s: failed to post send reply WR: %d\n",
		       URMA_SERVER_NAME, ret);
		return ret;
	}

	/* Wait for send completion */
	ret = urma_server_poll_jfc(ctx->jfc, &cr, URMA_DEMO_POLL_TIMEOUT_MS);
	if (ret) {
		pr_err("%s: send reply completion timeout\n", URMA_SERVER_NAME);
		return ret;
	}

	if (cr.status != UBCORE_CR_SUCCESS) {
		pr_err("%s: send reply failed with status %d\n",
		       URMA_SERVER_NAME, cr.status);
		return -EIO;
	}

	pr_info("%s: Reply sent successfully\n", URMA_SERVER_NAME);
	return 0;
}

/*
 * Process received message from client
 */
static int urma_server_process_message(struct urma_server_ctx *ctx)
{
	struct urma_demo_seg_info_msg *msg;
	u32 bytes_read = 0;
	int ret;

	msg = (struct urma_demo_seg_info_msg *)ctx->recv_buf;

	if (msg->msg_type != URMA_DEMO_MSG_TYPE_SEG_INFO) {
		pr_err("%s: unexpected message type: %u\n", URMA_SERVER_NAME,
		       msg->msg_type);
		return -EINVAL;
	}

	pr_info("%s: Received segment info from client\n", URMA_SERVER_NAME);

	/* Import client's segment */
	ret = urma_server_import_client_seg(ctx, msg);
	if (ret) {
		urma_server_send_reply(ctx, URMA_DEMO_STATUS_ERROR, 0);
		return ret;
	}

	/* Perform RDMA read */
	ret = urma_server_rdma_read(ctx);
	if (ret) {
		urma_server_send_reply(ctx, URMA_DEMO_STATUS_ERROR, 0);
		goto cleanup;
	}

	bytes_read = URMA_DEMO_CLIENT_BUF_SIZE;

	/* Send reply */
	ret = urma_server_send_reply(ctx, URMA_DEMO_STATUS_SUCCESS, bytes_read);

cleanup:
	/* Cleanup imported segment (always unimport per-request) */
	if (ctx->client_seg) {
		ubcore_unimport_seg(ctx->client_seg);
		ctx->client_seg = NULL;
	}
	/* Only unimport jetty if not early-imported (keep persistent) */
	if (ctx->client_tjetty && !ctx->jetty_imported_early) {
		ubcore_unimport_jetty(ctx->client_tjetty);
		ctx->client_tjetty = NULL;
	}

	return ret;
}

/*
 * Main server loop - wait for client message and process it
 */
static int urma_server_wait_and_process(struct urma_server_ctx *ctx)
{
	struct ubcore_cr cr = { 0 };
	int ret;

	if (!ctx->initialized) {
		pr_err("%s: server not initialized\n", URMA_SERVER_NAME);
		return -EINVAL;
	}

	/* Post receive buffer */
	ret = urma_server_post_recv(ctx);
	if (ret)
		return ret;

	ctx->waiting = true;
	pr_info("%s: Waiting for client message...\n", URMA_SERVER_NAME);

	/* Wait for receive completion */
	ret = urma_server_poll_jfc(ctx->jfc, &cr,
				   URMA_DEMO_POLL_TIMEOUT_MS * 10);
	ctx->waiting = false;

	if (ret == -ETIMEDOUT) {
		pr_info("%s: No message received (timeout)\n",
			URMA_SERVER_NAME);
		return ret;
	}
	if (ret) {
		pr_err("%s: receive failed: %d\n", URMA_SERVER_NAME, ret);
		return ret;
	}

	if (cr.status != UBCORE_CR_SUCCESS) {
		pr_err("%s: receive completed with error status %d\n",
		       URMA_SERVER_NAME, cr.status);
		return -EIO;
	}

	pr_info("%s: Received message from client\n", URMA_SERVER_NAME);

	/* Process the message */
	return urma_server_process_message(ctx);
}

/*
 * Debugfs trigger file write handler
 */
static ssize_t urma_server_trigger_write(struct file *file,
					 const char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct urma_server_ctx *ctx = &g_server_ctx;
	int ret;

	if (!ctx->initialized) {
		pr_err("%s: server not initialized\n", URMA_SERVER_NAME);
		return -EINVAL;
	}

	ret = urma_server_wait_and_process(ctx);
	if (ret && ret != -ETIMEDOUT)
		return ret;

	return count;
}

static const struct file_operations trigger_fops = {
	.owner = THIS_MODULE,
	.write = urma_server_trigger_write,
};

/*
 * Import client jetty early using module parameters
 * This allows bidirectional communication setup before any data exchange
 */
static int urma_server_import_client_jetty_early(struct urma_server_ctx *ctx)
{
	struct ubcore_tjetty_cfg tjetty_cfg = { 0 };
	u8 eid_raw[URMA_DEMO_EID_SIZE];
	char eid_str[64];
	int ret;

	/* Parse client EID from module parameter */
	ret = urma_demo_parse_eid(client_eid, eid_raw);
	if (ret) {
		pr_err("%s: failed to parse client_eid: %s\n", URMA_SERVER_NAME,
		       client_eid);
		return ret;
	}

	/* Configure target jetty */
	memcpy(tjetty_cfg.id.eid.raw, eid_raw, URMA_DEMO_EID_SIZE);
	tjetty_cfg.id.id = client_jetty_id;
	tjetty_cfg.trans_mode = UBCORE_TP_RM;
	tjetty_cfg.eid_index = ctx->eid_index;
	tjetty_cfg.type = UBCORE_JFR;
	tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;

	ctx->client_tjetty =
		ubcore_import_jetty(ctx->ub_dev, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->client_tjetty)) {
		pr_err("%s: failed to import client jetty early\n",
		       URMA_SERVER_NAME);
		ctx->client_tjetty = NULL;
		return PTR_ERR(ctx->client_tjetty);
	}

	ctx->jetty_imported_early = true;

	urma_demo_format_eid(eid_raw, eid_str, sizeof(eid_str));
	pr_info("%s: Client jetty imported early (eid=%s, jetty_id=%u)\n",
		URMA_SERVER_NAME, eid_str, client_jetty_id);

	return 0;
}

/*
 * ubcore client add device callback
 */
static int urma_server_add_dev(struct ubcore_device *ub_dev)
{
	struct urma_server_ctx *ctx = &g_server_ctx;
	int ret;
	char eid_str[64];

	/* Check if we're looking for a specific device */
	if (strlen(device_name) > 0 &&
	    strcmp(device_name, ub_dev->dev_name) != 0) {
		pr_info("%s: Skipping device %s (waiting for %s)\n",
			URMA_SERVER_NAME, ub_dev->dev_name, device_name);
		return -ENODEV;
	}

	/* Check transport type */
	if (ub_dev->transport_type != UBCORE_TRANSPORT_UB) {
		pr_info("%s: Skipping non-UB device %s\n", URMA_SERVER_NAME,
			ub_dev->dev_name);
		return -ENODEV;
	}

	/* Select EID index */
	ret = urma_server_select_eid_index(ub_dev, &ctx->eid_index);
	if (ret)
		return ret;

	pr_info("%s: Using device %s\n", URMA_SERVER_NAME, ub_dev->dev_name);
	ctx->ub_dev = ub_dev;

	/* Create URMA resources */
	ret = urma_server_create_resources(ctx);
	if (ret) {
		pr_err("%s: failed to create resources: %d\n", URMA_SERVER_NAME,
		       ret);
		ctx->ub_dev = NULL;
		return ret;
	}

	/* Optionally import client jetty early if parameters are provided */
	if (strlen(client_eid) > 0 && client_jetty_id != 0) {
		ret = urma_server_import_client_jetty_early(ctx);
		if (ret) {
			pr_warn("%s: early jetty import failed (%d), will import later from message\n",
				URMA_SERVER_NAME, ret);
			/* Non-fatal - can still import later from message */
		}
	}

	/* Create debugfs interface */
	ctx->debugfs_dir = debugfs_create_dir(URMA_SERVER_NAME, NULL);
	if (!IS_ERR_OR_NULL(ctx->debugfs_dir)) {
		debugfs_create_file("trigger", 0200, ctx->debugfs_dir, ctx,
				    &trigger_fops);
	}

	urma_demo_format_eid(ctx->jetty->jetty_id.eid.raw, eid_str,
			     sizeof(eid_str));
	pr_info("%s: Server ready. EID=%s, jetty_id=%u\n", URMA_SERVER_NAME,
		eid_str, ctx->jetty->jetty_id.id);
	pr_info("%s: Write to /sys/kernel/debug/%s/trigger to wait for client\n",
		URMA_SERVER_NAME, URMA_SERVER_NAME);

	return 0;
}

/*
 * ubcore client remove device callback
 */
static void urma_server_remove_dev(struct ubcore_device *ub_dev,
				   void *client_data)
{
	struct urma_server_ctx *ctx = &g_server_ctx;

	if (ctx->ub_dev != ub_dev)
		return;

	pr_info("%s: Removing device %s\n", URMA_SERVER_NAME, ub_dev->dev_name);

	/* Remove debugfs */
	if (ctx->debugfs_dir) {
		debugfs_remove_recursive(ctx->debugfs_dir);
		ctx->debugfs_dir = NULL;
	}

	/* Cleanup imported resources */
	if (ctx->client_seg)
		ubcore_unimport_seg(ctx->client_seg);
	if (ctx->client_tjetty)
		ubcore_unimport_jetty(ctx->client_tjetty);

	/* Cleanup local resources */
	if (ctx->read_seg)
		ubcore_unregister_seg(ctx->read_seg);
	if (ctx->read_buf)
		kfree(ctx->read_buf);
	if (ctx->send_seg)
		ubcore_unregister_seg(ctx->send_seg);
	if (ctx->send_buf)
		kfree(ctx->send_buf);
	if (ctx->recv_seg)
		ubcore_unregister_seg(ctx->recv_seg);
	if (ctx->recv_buf)
		kfree(ctx->recv_buf);
	if (ctx->jetty)
		ubcore_delete_jetty(ctx->jetty);
	if (ctx->jfr)
		ubcore_delete_jfr(ctx->jfr);
	if (ctx->jfc)
		ubcore_delete_jfc(ctx->jfc);

	ctx->initialized = false;
	ctx->ub_dev = NULL;
}

static struct ubcore_client urma_server = {
	.client_name = URMA_SERVER_NAME,
	.add = urma_server_add_dev,
	.remove = urma_server_remove_dev,
};

static int __init urma_server_init(void)
{
	int ret;

	pr_info("%s: Loading URMA server demo module\n", URMA_SERVER_NAME);

	memset(&g_server_ctx, 0, sizeof(g_server_ctx));
	g_server_ctx.ub_client = urma_server;

	ret = ubcore_register_client(&g_server_ctx.ub_client);
	if (ret) {
		pr_err("%s: failed to register ubcore client: %d\n",
		       URMA_SERVER_NAME, ret);
		return ret;
	}

	pr_info("%s: Module loaded successfully\n", URMA_SERVER_NAME);
	return 0;
}

static void __exit urma_server_exit(void)
{
	pr_info("%s: Unloading URMA server demo module\n", URMA_SERVER_NAME);

	ubcore_unregister_client(&g_server_ctx.ub_client);

	pr_info("%s: Module unloaded\n", URMA_SERVER_NAME);
}

module_init(urma_server_init);
module_exit(urma_server_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("URMA Demo");
MODULE_DESCRIPTION(
	"URMA Kernel Server Demo - receives segment info, performs RDMA read, sends reply");
MODULE_VERSION("1.0");
