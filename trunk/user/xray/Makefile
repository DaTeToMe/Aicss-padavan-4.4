THISDIR := $(shell pwd)
PKG_NAME := xray
PKG_VERSION := 1.8.23
PKG_ARCH := mips32le
PKG_SOURCE := Xray-linux-$(PKG_ARCH).zip
PKG_SOURCE_URL := https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)/$(PKG_SOURCE)
PKG_BUILD_DIR := $(THISDIR)/build

all: download extract build compress
	@echo "xray build done!"
	@echo "Final binary size:"
	@ls -lh $(PKG_BUILD_DIR)/xray_final

download:
	@if [ ! -f $(PKG_SOURCE) ]; then \
		echo "Downloading Xray v$(PKG_VERSION)..."; \
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
	@if [ -f $(PKG_BUILD_DIR)/xray_softfloat ]; then \
		cp $(PKG_BUILD_DIR)/xray_softfloat $(PKG_BUILD_DIR)/xray_final; \
	elif [ -f $(PKG_BUILD_DIR)/xray ]; then \
		cp $(PKG_BUILD_DIR)/xray $(PKG_BUILD_DIR)/xray_final; \
	else \
		echo "Error: No xray binary found"; exit 1; \
	fi
	@chmod +x $(PKG_BUILD_DIR)/xray_final
	@echo "Original size: $$(ls -lh $(PKG_BUILD_DIR)/xray_final | awk '{print $$5}')"

strip: build
	@echo "Checking if binary needs stripping..."
	@if command -v $(CROSS_COMPILE)strip >/dev/null 2>&1; then \
		echo "Stripping with $(CROSS_COMPILE)strip..."; \
		$(CROSS_COMPILE)strip --strip-all $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		echo "Strip failed or binary already stripped"; \
	elif command -v mipsel-linux-strip >/dev/null 2>&1; then \
		echo "Stripping with mipsel-linux-strip..."; \
		mipsel-linux-strip --strip-all $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		echo "Strip failed or binary already stripped"; \
	else \
		echo "Cross-strip tool not found, skipping (binary may already be stripped)"; \
	fi
	@echo "After strip: $(ls -lh $(PKG_BUILD_DIR)/xray_final | awk '{print $5}')"

compress: build
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing with UPX..."; \
		upx --ultra-brute $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		upx --best --lzma $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		upx --best $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		upx -9 $(PKG_BUILD_DIR)/xray_final 2>/dev/null || \
		echo "Note: UPX compression skipped (binary may already be compressed)"; \
	else \
		echo "UPX not found. Install: apt-get install upx-ucl"; \
	fi
	@echo "Final size: $(ls -lh $(PKG_BUILD_DIR)/xray_final | awk '{print $5}')"

clean:
	@rm -rf $(PKG_BUILD_DIR)
	@rm -f $(PKG_SOURCE)

romfs:
	$(ROMFSINST) -p +x $(PKG_BUILD_DIR)/xray_final /usr/bin/xray

.PHONY: all download extract build compress clean romfs
