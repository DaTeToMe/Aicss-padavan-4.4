THISDIR = $(shell pwd)
PKG_NAME:=xray
PKG_VERSION:=1.8.24
# 预编译二进制文件名（根据你的架构选择）
# mipsle = 小端 MIPS (大多数路由器)
# mips = 大端 MIPS
PKG_ARCH:=linux-mipsle
PKG_SOURCE:=Xray-$(PKG_ARCH).zip
PKG_SOURCE_URL:=https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)/$(PKG_SOURCE)
PKG_BUILD_DIR:=$(THISDIR)/build

all: download extract build

download:
	@echo "Downloading Xray from GitHub..."
	@if [ ! -f $(PKG_SOURCE) ]; then \
		wget --no-check-certificate -O $(PKG_SOURCE) $(PKG_SOURCE_URL) || \
		{ echo "Failed to download Xray"; exit 1; }; \
	else \
		echo "Xray archive already exists, skipping download"; \
	fi

extract: download
	@echo "Extracting Xray..."
	@mkdir -p $(PKG_BUILD_DIR)
	@unzip -o $(PKG_SOURCE) -d $(PKG_BUILD_DIR)
	@chmod +x $(PKG_BUILD_DIR)/xray

build: extract
	@echo "Using prebuilt Xray binary"
	# 可选：使用 UPX 进一步压缩（如果编译环境有 UPX）
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing with UPX..."; \
		upx --best --lzma $(PKG_BUILD_DIR)/xray || upx -9 $(PKG_BUILD_DIR)/xray || true; \
	else \
		echo "UPX not found, skipping compression"; \
	fi

clean:
	@echo "Cleaning Xray build files..."
	@rm -rf $(PKG_BUILD_DIR)
	@rm -f $(PKG_SOURCE)

romfs:
	$(ROMFSINST) /usr/bin/xray
	$(ROMFSINST) -p +x $(PKG_BUILD_DIR)/xray /usr/bin/xray
