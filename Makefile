# SPDX-License-Identifier: GPL-2.0
#
# Makefile for URMA Kernel Module Demo
#
# This Makefile builds two kernel modules:
#   - urma_demo_client.ko: Client module that sends segment info
#   - urma_demo_server.ko: Server module that performs RDMA read
#

# Module names
obj-m += urma_demo_client.o
obj-m += urma_demo_server.o

# Source files
urma_demo_client-y := urma_client.o
urma_demo_server-y := urma_server.o

# Kernel source directory (can be overridden)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Include path for ubcore headers
# Adjust UBCORE_INC to point to your ubcore header location
UBCORE_INC ?= $(CURDIR)/../include

# Extra compiler flags - passed to kernel build via EXTRA_CFLAGS
EXTRA_CFLAGS := -I$(UBCORE_INC) -I$(CURDIR)

# Also set ccflags-y for when Makefile is read by kbuild
ccflags-y += -I$(UBCORE_INC)
ccflags-y += -I$(CURDIR)

# Default target
all: modules

# Build modules
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f Module.symvers modules.order

# Install modules (requires root)
install: modules
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
	depmod -a

# Uninstall modules
uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/urma_demo_client.ko
	rm -f /lib/modules/$(shell uname -r)/extra/urma_demo_server.ko
	depmod -a

# Load server module
load-server:
	@echo "Loading URMA server module..."
	insmod urma_demo_server.ko
	@echo "Check dmesg for server EID and jetty_id"

# Load client module (requires server_eid and server_jetty_id)
load-client:
ifndef SERVER_EID
	$(error SERVER_EID is not set. Usage: make load-client SERVER_EID=xx:xx:... SERVER_JETTY_ID=123)
endif
ifndef SERVER_JETTY_ID
	$(error SERVER_JETTY_ID is not set. Usage: make load-client SERVER_EID=xx:xx:... SERVER_JETTY_ID=123)
endif
	@echo "Loading URMA client module..."
	insmod urma_demo_client.ko server_eid=$(SERVER_EID) server_jetty_id=$(SERVER_JETTY_ID)

# Unload modules
unload:
	-rmmod urma_demo_client 2>/dev/null || true
	-rmmod urma_demo_server 2>/dev/null || true

# Trigger server to wait for client
trigger-server:
	@echo "Triggering server to wait for client message..."
	echo 1 > /sys/kernel/debug/urma_demo_server/trigger

# Show kernel log
log:
	dmesg | grep -E "urma_demo_(client|server)" | tail -50

# Help
help:
	@echo "URMA Kernel Module Demo - Makefile targets:"
	@echo ""
	@echo "  make              - Build both client and server modules"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make install      - Install modules to system"
	@echo "  make uninstall    - Remove modules from system"
	@echo ""
	@echo "  make load-server  - Load server module"
	@echo "  make load-client SERVER_EID=<eid> SERVER_JETTY_ID=<id>"
	@echo "                    - Load client module with server connection info"
	@echo "  make unload       - Unload both modules"
	@echo ""
	@echo "  make trigger-server - Trigger server to wait for client"
	@echo "  make log          - Show recent kernel log for these modules"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR              - Kernel build directory (default: /lib/modules/$(shell uname -r)/build)"
	@echo "  UBCORE_INC        - ubcore header include path (default: $(CURDIR)/../include)"
	@echo ""
	@echo "Example usage:"
	@echo "  # On server machine:"
	@echo "  make && make load-server"
	@echo "  # Note the EID and jetty_id from dmesg"
	@echo "  make trigger-server"
	@echo ""
	@echo "  # On client machine:"
	@echo "  make && make load-client SERVER_EID=00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:01 SERVER_JETTY_ID=1"

.PHONY: all modules clean install uninstall load-server load-client unload trigger-server log help
