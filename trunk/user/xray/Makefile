THISDIR := $(shell pwd)
PKG_NAME := xray
PKG_VERSION := 1.8.23
PKG_ARCH := mips32le
PKG_SOURCE := Xray-linux-$(PKG_ARCH).zip
PKG_SOURCE_URL := https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)/$(PKG_SOURCE)
PKG_BUILD_DIR := $(THISDIR)/build

all: download extract build compress
	@echo "xray build done!"

download:
	@if [ ! -f $(PKG_SOURCE) ]; then \
		echo "Downloading Xray v$(PKG_VERSION) from GitHub..."; \
		wget --no-check-certificate -O $(PKG_SOURCE) $(PKG_SOURCE_URL) || \
		{ echo "Failed to download Xray"; exit 1; }; \
	else \
		echo "Xray archive already exists, skipping download"; \
	fi

extract: download
	@echo "Extracting Xray..."
	@mkdir -p $(PKG_BUILD_DIR)
	@unzip -o $(PKG_SOURCE) -d $(PKG_BUILD_DIR)
	@echo "Archive contents:"
	@ls -lh $(PKG_BUILD_DIR)

build: extract
	@echo "Preparing Xray binary..."
	@if [ -f $(PKG_BUILD_DIR)/xray_softfloat ]; then \
		echo "Using xray_softfloat version for MT7621 compatibility"; \
		cp $(PKG_BUILD_DIR)/xray_softfloat $(PKG_BUILD_DIR)/xray_final; \
	elif [ -f $(PKG_BUILD_DIR)/xray ]; then \
		echo "Using standard xray binary"; \
		cp $(PKG_BUILD_DIR)/xray $(PKG_BUILD_DIR)/xray_final; \
	else \
		echo "Error: No xray binary found in archive"; \
		exit 1; \
	fi
	@chmod +x $(PKG_BUILD_DIR)/xray_final

compress: build
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing xray with UPX..."; \
		upx --best --lzma $(PKG_BUILD_DIR)/xray_final || upx -9 $(PKG_BUILD_DIR)/xray_final || echo "UPX compression failed, using original binary"; \
		echo "UPX compression done"; \
	else \
		echo "UPX not found, skipping compression"; \
	fi

clean:
	@echo "Cleaning Xray build files..."
	@rm -rf $(PKG_BUILD_DIR)
	@rm -f $(PKG_SOURCE)

romfs:
	$(ROMFSINST) -p +x $(PKG_BUILD_DIR)/xray_final /usr/bin/xray
