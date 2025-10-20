THISDIR := $(shell pwd)
PKG_NAME := xray
PKG_VERSION := 1.8.23
PKG_ARCH := mips32le
PKG_SOURCE := Xray-core-v$(PKG_VERSION).zip
PKG_SOURCE_URL := https://github.com/XTLS/Xray-core/archive/refs/tags/v$(PKG_VERSION).zip
PKG_BUILD_DIR := $(THISDIR)/build

all: download extract build compress
	@echo "Xray build completed."

download:
	@if [ ! -f $(PKG_SOURCE) ]; then \
		echo "Downloading Xray-Core v$(PKG_VERSION) source..."; \
		wget --no-check-certificate -O $(PKG_SOURCE) $(PKG_SOURCE_URL) || \
		{ echo "Download failed"; exit 1; }; \
	else \
		echo "Source archive exists, skipping download."; \
	fi

extract: download
	@echo "Extracting source..."
	@mkdir -p $(PKG_BUILD_DIR)
	@unzip -o $(PKG_SOURCE) -d $(PKG_BUILD_DIR)
	@mv $(PKG_BUILD_DIR)/Xray-core-v$(PKG_VERSION) $(PKG_BUILD_DIR)/src

build: extract
	@echo "Building Xray binary for MIPS32le..."
	@cd $(PKG_BUILD_DIR)/src && \
	GOOS=linux GOARCH=mipsle CGO_ENABLED=0 go mod download && \
	go build -ldflags="-s -w -buildid=" -trimpath -buildvcs=false -o xray_final ./ || \
	{ echo "Build failed"; exit 1; }
	@chmod +x $(PKG_BUILD_DIR)/src/xray_final
	@mv $(PKG_BUILD_DIR)/src/xray_final $(PKG_BUILD_DIR)/

compress: build
	@echo "Optimizing binary..."
	@strip --strip-all $(PKG_BUILD_DIR)/xray_final 2>/dev/null || echo "Strip skipped."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(PKG_BUILD_DIR)/xray_final || upx -9 $(PKG_BUILD_DIR)/xray_final || echo "UPX failed, using stripped binary."; \
	fi

clean:
	@echo "Cleaning build files..."
	@rm -rf $(PKG_BUILD_DIR)
	@rm -f $(PKG_SOURCE)

romfs:
	$(ROMFSINST) -p +x $(PKG_BUILD_DIR)/xray_final /usr/bin/xray
