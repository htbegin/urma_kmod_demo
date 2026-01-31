/* SPDX-License-Identifier: GPL-2.0 */
/*
 * URMA Kernel Module Demo - Common Definitions
 *
 * This header contains shared structures and constants used by both
 * the client and server kernel modules for URMA-based communication.
 *
 * Copyright (c) 2024
 */

#ifndef URMA_DEMO_COMMON_H
#define URMA_DEMO_COMMON_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

/* Buffer sizes */
#define URMA_DEMO_CLIENT_BUF_SIZE 4096 /* 4KB client buffer for RDMA read */
#define URMA_DEMO_MSG_BUF_SIZE 256 /* Message buffer size */
#define URMA_DEMO_SAMPLE_DATA_SIZE 64 /* Sample data in reply */

/* EID size */
#define URMA_DEMO_EID_SIZE 16

/* Completion queue depth */
#define URMA_DEMO_JFC_DEPTH 64
#define URMA_DEMO_JFR_DEPTH 32
#define URMA_DEMO_JFS_DEPTH 32

/* Timeout values */
#define URMA_DEMO_POLL_TIMEOUT_MS 5000 /* 5 seconds */
#define URMA_DEMO_POLL_INTERVAL_US 100 /* 100 microseconds */

/* Magic pattern to fill client buffer for verification */
#define URMA_DEMO_MAGIC_PATTERN 0xDE

/* Message types */
#define URMA_DEMO_MSG_TYPE_SEG_INFO 0x01 /* Client sends segment info */
#define URMA_DEMO_MSG_TYPE_REPLY 0x02 /* Server sends reply */

/* Status codes */
#define URMA_DEMO_STATUS_SUCCESS 0
#define URMA_DEMO_STATUS_ERROR 1
#define URMA_DEMO_STATUS_TIMEOUT 2

/*
 * Message from client to server containing segment information
 * for RDMA read operation.
 *
 * Total size: 64 bytes
 */
struct urma_demo_seg_info_msg {
	u8 msg_type; /* URMA_DEMO_MSG_TYPE_SEG_INFO */
	u8 reserved1[3]; /* Alignment padding */
	u64 seg_va; /* Virtual address of registered segment */
	u32 seg_len; /* Length of segment (4096) */
	u32 token; /* Segment access token */
	u32 token_id; /* Token ID */
	u8 src_eid[URMA_DEMO_EID_SIZE]; /* Client's EID (16 bytes) */
	u32 src_jetty_id; /* Client's jetty ID for reply */
	u32 src_jetty_token; /* Client's jetty token (plain text) */
	u8 reserved2[16]; /* Padding to 64 bytes */
} __packed;

/*
 * Reply message from server to client after RDMA read operation.
 *
 * Total size: 128 bytes
 */
struct urma_demo_reply_msg {
	u8 msg_type; /* URMA_DEMO_MSG_TYPE_REPLY */
	u8 reserved1[3]; /* Alignment padding */
	u32 status; /* Operation status */
	u32 bytes_read; /* Number of bytes read via RDMA */
	u8 sample_data[URMA_DEMO_SAMPLE_DATA_SIZE]; /* First N bytes of read data */
	u8 reserved2[52]; /* Padding to 128 bytes */
} __packed;

/*
 * Helper to parse EID string (colon-separated hex) to raw bytes
 * Format: "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
 * Returns 0 on success, negative on error
 */
static inline int urma_demo_parse_eid(const char *eid_str, u8 *eid_raw)
{
	int i;
	unsigned int vals[URMA_DEMO_EID_SIZE];
	int ret;

	if (!eid_str || !eid_raw)
		return -EINVAL;

	/* Parse colon-separated hex bytes */
	ret = sscanf(eid_str,
		     "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		     "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		     &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5],
		     &vals[6], &vals[7], &vals[8], &vals[9], &vals[10],
		     &vals[11], &vals[12], &vals[13], &vals[14], &vals[15]);

	if (ret == URMA_DEMO_EID_SIZE) {
		for (i = 0; i < URMA_DEMO_EID_SIZE; i++)
			eid_raw[i] = (u8)vals[i];
		return 0;
	}

	/* Try IPv6-like format without colons between pairs */
	ret = sscanf(eid_str,
		     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		     "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		     &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5],
		     &vals[6], &vals[7], &vals[8], &vals[9], &vals[10],
		     &vals[11], &vals[12], &vals[13], &vals[14], &vals[15]);

	if (ret == URMA_DEMO_EID_SIZE) {
		for (i = 0; i < URMA_DEMO_EID_SIZE; i++)
			eid_raw[i] = (u8)vals[i];
		return 0;
	}

	return -EINVAL;
}

/*
 * Helper to format EID bytes to string
 */
static inline void urma_demo_format_eid(const u8 *eid_raw, char *buf,
					size_t len)
{
	snprintf(buf, len,
		 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		 eid_raw[0], eid_raw[1], eid_raw[2], eid_raw[3], eid_raw[4],
		 eid_raw[5], eid_raw[6], eid_raw[7], eid_raw[8], eid_raw[9],
		 eid_raw[10], eid_raw[11], eid_raw[12], eid_raw[13],
		 eid_raw[14], eid_raw[15]);
}

#endif /* URMA_DEMO_COMMON_H */
