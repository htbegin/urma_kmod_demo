# URMA Kernel Module Demo

This project demonstrates how to use the URMA (Unified Remote Memory Access) kernel API (ubcore) for RDMA operations between two kernel modules.

## Overview

The demo consists of two kernel modules:

| Module | Description |
|--------|-------------|
| `urma_demo_server.ko` | Server that imports the DMA-mapped UBVA, performs RDMA READ, and returns CRC32 |
| `urma_demo_client.ko` | Client that DMA-maps source pages, sends segment info, and verifies CRC32 |

### Communication Flow

```
CLIENT (Machine A)                     SERVER (Machine B)
---------------------                  ---------------------
1. Load module with                    1. Load module
   server_eid, server_jetty               (prints EID & jetty_id)
2. Register 16KB buffer                2. Trigger to wait for client
   (filled with 0xDE pattern)
3. DMA-map page sgtable
4. SEND seg_info ----------------------> 3. RECV seg_info
                                        4. Import client's DMA-mapped UBVA
                  <---- RDMA READ ----- 5. RDMA READ client's 16KB buffer
5. RECV reply <------------------------ 6. SEND reply with sample data + CRC32
6. Verify bytes_read and CRC32
```

## Prerequisites

- Linux kernel with ubcore module loaded
- URMA-capable network device (e.g., ROC/HNS3)
- Kernel headers installed
- Two machines connected via URMA-capable network

## Building

```bash
cd urma_kmod_demo

# Build with default include path (../include)
make

# Or specify custom ubcore header location
make UBCORE_INC=/path/to/ubcore/headers

# Or specify custom kernel build directory
make KDIR=/lib/modules/5.10.0/build
```

### Build Targets

```bash
make              # Build both modules
make clean        # Clean build artifacts
make install      # Install modules to system
make uninstall    # Remove modules from system
make help         # Show all available targets
```

## Usage

### Step 1: Load Server Module (on server machine)

```bash
# Load the server module
sudo insmod urma_demo_server.ko

# Or use make target
sudo make load-server

# Check kernel log for server's EID and jetty_id
dmesg | grep urma_demo_server
# Example output:
# urma_demo_server: Server ready - EID: 00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:02, jetty_id: 120
```

Note down the EID and jetty_id values displayed.

### Step 2: Trigger Server to Wait for Client

```bash
# Trigger the server to start waiting for client message
echo 1 | sudo tee /sys/kernel/debug/urma_demo_server/trigger

# Or use make target
sudo make trigger-server
```

### Step 3: Load Client Module (on client machine)

```bash
# Load client with server connection info
sudo insmod urma_demo_client.ko \
    server_eid=00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:02 \
    server_jetty=120

# Or use make target
sudo make load-client \
    SERVER_EID=00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:02 \
    SERVER_JETTY=120
```

### Step 4: Verify Operation

```bash
# Check kernel logs on both machines
dmesg | grep urma_demo

# Or use make target
make log
```

Expected log output on client:
```
urma_demo_client: Registered memory segment, VA=0x..., token=...
urma_demo_client: Sent segment info to server
urma_demo_client: Server successfully read 16384 bytes via RDMA
urma_demo_client: Server CRC32: 0x...
urma_demo_client: Data CRC32 verification PASSED!
```

Expected log output on server:
```
urma_demo_server: Received segment info from client
urma_demo_server: Imported client segment, VA=0x...
urma_demo_server: RDMA read completed successfully, read 16384 bytes
urma_demo_server: Sending reply: status=0, bytes_read=16384, crc32=0x...
urma_demo_server: Reply sent successfully
```

### Step 5: Unload Modules

```bash
# Unload both modules
sudo rmmod urma_demo_client
sudo rmmod urma_demo_server

# Or use make target
sudo make unload
```

## Module Parameters

### urma_demo_client.ko

| Parameter | Type | Description |
|-----------|------|-------------|
| `server_eid` | string | Server's EID in colon-separated hex format |
| `server_jetty` | uint | Server jetty ID (default: 120) |
| `local_eid` | string | Local EID to select EID index (optional) |

### urma_demo_server.ko

| Parameter | Type | Description |
|-----------|------|-------------|
| `device_name` | string | URMA device name (default: first available) |
| `local_eid` | string | Local EID to select EID index (optional) |
| `server_jetty` | uint | Server jetty ID (default: 120) |
| `client_eid` | string | Client's EID for early jetty import (optional) |
| `client_jetty` | uint | Client jetty ID (default: 110) |

#### Early Client Jetty Import

By default, the server imports the client's jetty after receiving the first message. For scenarios requiring early bidirectional communication setup (similar to RC connection mode), you can specify `client_eid` and `client_jetty` at module load time:

```bash
# Load server with early client jetty import
sudo insmod urma_demo_server.ko \
    client_eid=00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:01 \
    client_jetty=110
```

When both parameters are provided, the server imports the client's jetty immediately during initialization. This imported jetty persists across multiple client requests (not cleaned up after each message exchange).

## EID Format

EID (Endpoint Identifier) is a 16-byte identifier, typically represented as:
- Colon-separated hex: `00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:01`
- For IPv4-mapped addresses, last 4 bytes contain the IP (e.g., `c0:a8:01:01` = 192.168.1.1)

## Debugging

### Enable Verbose Logging

```bash
# Increase kernel log level
echo 8 | sudo tee /proc/sys/kernel/printk

# Watch logs in real-time
dmesg -wH | grep urma_demo
```

### Check URMA Device Status

```bash
# List available URMA devices
ls /sys/class/ubcore/

# Check device info
cat /sys/class/ubcore/*/eid
```

### Common Issues

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| "No URMA device found" | ubcore not loaded or no URMA device | Load ubcore module, check device availability |
| "Timeout waiting for completion" | Network issue or server not ready | Ensure server is triggered before client loads |
| "Failed to import segment" | Invalid segment info or network issue | Verify EID and connectivity |
| "Build fails with missing headers" | ubcore headers not found | Set UBCORE_INC to correct path |

## Architecture Details

### Transport Mode

This demo uses RM (Reliable Message) transport mode, which provides:
- Reliable delivery with acknowledgments
- Message-based semantics
- Suitable for control messages and small data transfers

### Memory Registration

The client allocates a 16KB source buffer with `alloc_pages()` and fills it with magic pattern (0xDE). It builds a page `sg_table`, maps it with `dma_map_sgtable()`, validates that DMA mapping produced one 16KB segment, and sends `sg_dma_address()` as the remote-visible UBVA. The server imports that DMA-mapped UBVA using `ubcore_import_seg()`. After RDMA READ completes, the server computes CRC32 over the read data and returns it to the client for full-buffer verification.

### RDMA Operations

1. **SEND/RECV**: Used for exchanging segment info and CRC32 reply messages
2. **RDMA READ**: Server reads the client's DMA-mapped source pages without CPU involvement on client side

## File Structure

```
urma_kmod_demo/
├── Makefile              # Build system
├── README.md             # This file
├── urma_demo_common.h    # Shared structures and constants
├── urma_client.c         # Client kernel module
└── urma_server.c         # Server kernel module
```

## License

SPDX-License-Identifier: GPL-2.0
