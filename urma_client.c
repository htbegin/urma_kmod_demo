// SPDX-License-Identifier: GPL-2.0
/*
 * URMA Kernel Module Demo - Client
 *
 * This module demonstrates URMA kernel API usage as a client:
 * 1. Registers a 4KB memory region
 * 2. Sends segment information to the server
 * 3. Waits for server to perform RDMA read and send reply
 *
 * Copyright (c) 2024
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/inet.h>

#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>

#include "urma_demo_common.h"

#define URMA_CLIENT_NAME "urma_demo_client"

/* Module parameters */
static char *server_eid = "";
module_param(server_eid, charp, 0444);
MODULE_PARM_DESC(
	server_eid,
	"Server EID in format xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx");

static unsigned int server_jetty_id;
module_param(server_jetty_id, uint, 0444);
MODULE_PARM_DESC(server_jetty_id, "Server jetty ID");

static unsigned int server_jetty_token;
module_param(server_jetty_token, uint, 0444);
MODULE_PARM_DESC(
	server_jetty_token,
	"Server jetty token for PLAIN_TEXT policy (required when token policy is enabled)");

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
	struct ubcore_target_seg *local_seg;

	/* Remote connection */
	struct ubcore_tjetty *tjetty;
	u8 server_eid_raw[URMA_DEMO_EID_SIZE];

	/* Buffers */
	void *data_buf; /* 4KB buffer for RDMA read */
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
	u32 jetty_token;
};

static struct urma_client_ctx g_client_ctx;

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
	char eid_str[64];

	/* Create JFC (completion queue) */
	jfc_cfg.depth = URMA_DEMO_JFC_DEPTH;
	jfc_cfg.flag.bs.lock_free = 0;

	ctx->jfc = ubcore_create_jfc(ctx->ub_dev, &jfc_cfg, NULL, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfc)) {
		pr_err("%s: failed to create JFC\n", URMA_CLIENT_NAME);
		return PTR_ERR(ctx->jfc);
	}
	pr_info("%s: JFC created, id=%u\n", URMA_CLIENT_NAME, ctx->jfc->id);

	/* Create JFR (receive queue) for RM mode */
	jfr_cfg.depth = URMA_DEMO_JFR_DEPTH;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_PLAIN_TEXT;
	get_random_bytes(&ctx->jetty_token, sizeof(ctx->jetty_token));
	if (ctx->jetty_token == 0)
		ctx->jetty_token = 1;
	jfr_cfg.token_value.token = ctx->jetty_token;
	jfr_cfg.trans_mode = UBCORE_TP_RM;
	jfr_cfg.eid_index = ctx->eid_index;
	jfr_cfg.max_sge = 1;
	jfr_cfg.min_rnr_timer = 12;
	jfr_cfg.jfc = ctx->jfc;

	ctx->jfr = ubcore_create_jfr(ctx->ub_dev, &jfr_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfr)) {
		pr_err("%s: failed to create JFR\n", URMA_CLIENT_NAME);
		ret = PTR_ERR(ctx->jfr);
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
		ret = PTR_ERR(ctx->jetty);
		goto err_delete_jfr;
	}

	urma_demo_format_eid(ctx->jetty->jetty_id.eid.raw, eid_str,
			     sizeof(eid_str));
	pr_info("%s: Jetty created, id=%u, eid=%s\n", URMA_CLIENT_NAME,
		ctx->jetty->jetty_id.id, eid_str);

	/* Allocate and register data buffer (4KB for RDMA read) */
	ctx->data_buf = kzalloc(URMA_DEMO_CLIENT_BUF_SIZE, GFP_KERNEL);
	if (!ctx->data_buf) {
		ret = -ENOMEM;
		goto err_delete_jetty;
	}

	/* Fill buffer with magic pattern for verification */
	memset(ctx->data_buf, URMA_DEMO_MAGIC_PATTERN,
	       URMA_DEMO_CLIENT_BUF_SIZE);

	/* Register data buffer as segment */
	seg_cfg.va = (u64)ctx->data_buf;
	seg_cfg.len = URMA_DEMO_CLIENT_BUF_SIZE;
	seg_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	seg_cfg.flag.bs.access = UBCORE_ACCESS_READ | UBCORE_ACCESS_WRITE;
	seg_cfg.eid_index = ctx->eid_index;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->local_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->local_seg)) {
		pr_err("%s: failed to register data segment\n",
		       URMA_CLIENT_NAME);
		ret = PTR_ERR(ctx->local_seg);
		goto err_free_data_buf;
	}
	pr_info("%s: Data segment registered, va=0x%llx, len=%llu, token=0x%x\n",
		URMA_CLIENT_NAME, ctx->local_seg->seg.ubva.va,
		ctx->local_seg->seg.len, seg_cfg.token_value.token);

	/* Allocate and register send buffer */
	ctx->send_buf = kzalloc(URMA_DEMO_MSG_BUF_SIZE, GFP_KERNEL);
	if (!ctx->send_buf) {
		ret = -ENOMEM;
		goto err_unreg_data_seg;
	}

	seg_cfg.va = (u64)ctx->send_buf;
	seg_cfg.len = URMA_DEMO_MSG_BUF_SIZE;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->send_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->send_seg)) {
		pr_err("%s: failed to register send segment\n",
		       URMA_CLIENT_NAME);
		ret = PTR_ERR(ctx->send_seg);
		goto err_free_send_buf;
	}

	/* Allocate and register receive buffer */
	ctx->recv_buf = kzalloc(URMA_DEMO_MSG_BUF_SIZE, GFP_KERNEL);
	if (!ctx->recv_buf) {
		ret = -ENOMEM;
		goto err_unreg_send_seg;
	}

	seg_cfg.va = (u64)ctx->recv_buf;
	seg_cfg.len = URMA_DEMO_MSG_BUF_SIZE;
	get_random_bytes(&seg_cfg.token_value.token,
			 sizeof(seg_cfg.token_value.token));

	ctx->recv_seg = ubcore_register_seg(ctx->ub_dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->recv_seg)) {
		pr_err("%s: failed to register recv segment\n",
		       URMA_CLIENT_NAME);
		ret = PTR_ERR(ctx->recv_seg);
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
err_unreg_data_seg:
	ubcore_unregister_seg(ctx->local_seg);
err_free_data_buf:
	kfree(ctx->data_buf);
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
	struct ubcore_tjetty_cfg tjetty_cfg = { 0 };
	char eid_str[64];

	if (strlen(server_eid) == 0 || server_jetty_id == 0) {
		pr_err("%s: server_eid and server_jetty_id must be specified\n",
		       URMA_CLIENT_NAME);
		return -EINVAL;
	}
	if (server_jetty_token == 0) {
		pr_err("%s: server_jetty_token must be specified for PLAIN_TEXT policy\n",
		       URMA_CLIENT_NAME);
		return -EINVAL;
	}

	/* Parse server EID */
	if (urma_demo_parse_eid(server_eid, ctx->server_eid_raw) != 0) {
		pr_err("%s: invalid server_eid format: %s\n", URMA_CLIENT_NAME,
		       server_eid);
		return -EINVAL;
	}

	urma_demo_format_eid(ctx->server_eid_raw, eid_str, sizeof(eid_str));
	pr_info("%s: Connecting to server EID=%s, jetty_id=%u\n",
		URMA_CLIENT_NAME, eid_str, server_jetty_id);

	/* Configure target jetty for import */
	memcpy(tjetty_cfg.id.eid.raw, ctx->server_eid_raw, URMA_DEMO_EID_SIZE);
	tjetty_cfg.id.id = server_jetty_id;
	tjetty_cfg.trans_mode = UBCORE_TP_RM;
	tjetty_cfg.eid_index = ctx->eid_index;
	tjetty_cfg.type = UBCORE_JFR; /* For RM mode, target is JFR */
	tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_PLAIN_TEXT;
	tjetty_cfg.token_value.token = server_jetty_token;

	/* Import server's jetty (for RM mode, this creates connection) */
	ctx->tjetty = ubcore_import_jetty(ctx->ub_dev, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->tjetty)) {
		pr_err("%s: failed to import server jetty\n", URMA_CLIENT_NAME);
		return PTR_ERR(ctx->tjetty);
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

	/* Prepare message */
	msg = (struct urma_demo_seg_info_msg *)ctx->send_buf;
	memset(msg, 0, sizeof(*msg));

	msg->msg_type = URMA_DEMO_MSG_TYPE_SEG_INFO;
	msg->seg_va = ctx->local_seg->seg.ubva.va;
	msg->seg_len = URMA_DEMO_CLIENT_BUF_SIZE;
	msg->token = 0; /* Token disabled */
	msg->token_id = ctx->local_seg->seg.token_id;
	memcpy(msg->src_eid, ctx->jetty->jetty_id.eid.raw, URMA_DEMO_EID_SIZE);
	msg->src_jetty_id = ctx->jetty->jetty_id.id;
	msg->src_jetty_token = ctx->jetty_token;

	pr_info("%s: Sending seg info: va=0x%llx, len=%u, jetty_id=%u\n",
		URMA_CLIENT_NAME, msg->seg_va, msg->seg_len, msg->src_jetty_id);

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
		pr_info("%s: Sample data: %02x %02x %02x %02x %02x %02x %02x %02x\n",
			URMA_CLIENT_NAME, reply->sample_data[0],
			reply->sample_data[1], reply->sample_data[2],
			reply->sample_data[3], reply->sample_data[4],
			reply->sample_data[5], reply->sample_data[6],
			reply->sample_data[7]);

		/* Verify the sample data matches our pattern */
		if (reply->sample_data[0] == URMA_DEMO_MAGIC_PATTERN) {
			pr_info("%s: Data verification PASSED!\n",
				URMA_CLIENT_NAME);
		} else {
			pr_warn("%s: Data verification FAILED - expected 0x%02x, got 0x%02x\n",
				URMA_CLIENT_NAME, URMA_DEMO_MAGIC_PATTERN,
				reply->sample_data[0]);
		}
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
	if (strlen(server_eid) > 0 && server_jetty_id > 0) {
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
		pr_info("%s: Load module with server_eid=<eid> server_jetty_id=<id> to run test\n",
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
	if (ctx->local_seg)
		ubcore_unregister_seg(ctx->local_seg);
	if (ctx->data_buf)
		kfree(ctx->data_buf);
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
