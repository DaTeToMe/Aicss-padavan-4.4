THISDIR := $(shell pwd)
PKG_NAME := v2ray
PKG_VERSION := 5.16.1
PKG_ARCH := mips32le
PKG_SOURCE := v2ray-linux-$(PKG_ARCH).zip
PKG_SOURCE_URL := https://github.com/v2fly/v2ray-core/releases/download/v$(PKG_VERSION)/$(PKG_SOURCE)
PKG_BUILD_DIR := $(THISDIR)/build

all: download extract build strip compress
	@echo "v2ray build done!"
	@echo "Final binary size:"
	@ls -lh $(PKG_BUILD_DIR)/v2ray_final

download:
	@if [ ! -f $(PKG_SOURCE) ]; then \
		echo "Downloading v2ray v$(PKG_VERSION)..."; \
		wget --no-check-certificate -O $(PKG_SOURCE) $(PKG_SOURCE_URL) || \
		{ echo "Download failed"; exit 1; }; \
	else \
		echo "Archive exists, skipping download"; \
	fi

extract: download
	@echo "Extracting..."
	@mkdir -p $(PKG_BUILD_DIR)
	@unzip -oq $(PKG_SOURCE) -d $(PKG_BUILD_DIR)

build: extract
	@echo "Preparing binary..."
	@if [ -f $(PKG_BUILD_DIR)/v2ray ]; then \
		cp $(PKG_BUILD_DIR)/v2ray $(PKG_BUILD_DIR)/v2ray_final; \
	elif [ -f $(PKG_BUILD_DIR)/*/v2ray ]; then \
		cp $(PKG_BUILD_DIR)/*/v2ray $(PKG_BUILD_DIR)/v2ray_final; \
	else \
		echo "Error: No v2ray binary found in $(PKG_BUILD_DIR)"; \
		echo "Contents of build directory:"; \
		ls -la $(PKG_BUILD_DIR)/; \
		exit 1; \
	fi
	@chmod +x $(PKG_BUILD_DIR)/v2ray_final
	@echo "Original size: $(ls -lh $(PKG_BUILD_DIR)/v2ray_final | awk '{print $5}')"

strip: build
	@echo "Checking if binary needs stripping..."
	@if command -v $(CROSS_COMPILE)strip >/dev/null 2>&1; then \
		echo "Stripping with $(CROSS_COMPILE)strip..."; \
		$(CROSS_COMPILE)strip --strip-all $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		echo "Strip failed or binary already stripped"; \
	elif command -v mipsel-linux-strip >/dev/null 2>&1; then \
		echo "Stripping with mipsel-linux-strip..."; \
		mipsel-linux-strip --strip-all $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		echo "Strip failed or binary already stripped"; \
	else \
		echo "Cross-strip tool not found, skipping (binary may already be stripped)"; \
	fi
	@echo "After strip: $$(ls -lh $(PKG_BUILD_DIR)/v2ray_final | awk '{print $$5}')"

compress: build
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing with UPX..."; \
		upx --ultra-brute $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		upx --best --lzma $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		upx --best $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		upx -9 $(PKG_BUILD_DIR)/v2ray_final 2>/dev/null || \
		echo "Note: UPX compression skipped (binary may already be compressed)"; \
	else \
		echo "UPX not found. Install: apt-get install upx-ucl"; \
	fi
	@echo "Final size: $$(ls -lh $(PKG_BUILD_DIR)/v2ray_final | awk '{print $$5}')"

clean:
	@rm -rf $(PKG_BUILD_DIR)
	@rm -f $(PKG_SOURCE)

romfs:
	$(ROMFSINST) -p +x $(PKG_BUILD_DIR)/v2ray_final /usr/bin/v2ray

.PHONY: all download extract build strip compress clean romfs
