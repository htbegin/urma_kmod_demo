# URMA Kernel Module Demo

This project demonstrates how to use the URMA (Unified Remote Memory Access) kernel API (ubcore) for RDMA operations between two kernel modules.

## Overview

The demo consists of two kernel modules:

| Module | Description |
|--------|-------------|
| `urma_demo_server.ko` | Server that receives segment info and performs RDMA READ |
| `urma_demo_client.ko` | Client that registers memory and sends segment info to server |

### Communication Flow

```
CLIENT (Machine A)                     SERVER (Machine B)
---------------------                  ---------------------
1. Load module with                    1. Load module
   server_eid, server_jetty               (prints EID & jetty_id)
2. Register 4KB buffer                 2. Trigger to wait for client
   (filled with 0xDE pattern)
3. SEND seg_info ----------------------> 3. RECV seg_info
                                        4. Import client's segment
                  <---- RDMA READ ----- 5. RDMA READ client's 4KB buffer
5. RECV reply <------------------------ 6. SEND reply with sample data
6. Verify sample data matches 0xDE
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
urma_demo_client: Received reply - status=0, bytes_read=4096
urma_demo_client: Sample data verification: SUCCESS
```

Expected log output on server:
```
urma_demo_server: Received segment info from client
urma_demo_server: Imported client segment, VA=0x...
urma_demo_server: RDMA READ completed, 4096 bytes
urma_demo_server: Sent reply to client
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
| `server_jetty_id` | uint | Legacy server jetty ID (overrides default when `server_jetty` not set) |
| `local_eid` | string | Local EID to select EID index (optional) |

### urma_demo_server.ko

| Parameter | Type | Description |
|-----------|------|-------------|
| `device_name` | string | URMA device name (default: first available) |
| `local_eid` | string | Local EID to select EID index (optional) |
| `server_jetty` | uint | Server jetty ID (default: 120) |
| `client_eid` | string | Client's EID for early jetty import (optional) |
| `client_jetty` | uint | Client jetty ID (default: 110) |
| `client_jetty_id` | uint | Legacy client jetty ID (overrides default when `client_jetty` not set) |

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

The client registers a 4KB buffer filled with magic pattern (0xDE) using `ubcore_register_seg()`. The server imports this segment using `ubcore_import_seg()` with the token received from the client.

### RDMA Operations

1. **SEND/RECV**: Used for exchanging segment info and reply messages
2. **RDMA READ**: Server reads client's registered memory without CPU involvement on client side

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
