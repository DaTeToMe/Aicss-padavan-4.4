include $(ROOTDIR)/rules.mk

PKG_NAME:=xray
PKG_VERSION:=1.8.24

# 预编译二进制文件名（根据你的架构选择）
# mipsle = 小端 MIPS (大多数路由器)
# mips = 大端 MIPS
PKG_ARCH:=linux-mipsle

PKG_SOURCE:=Xray-$(PKG_ARCH).zip
PKG_SOURCE_URL:=https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)/
PKG_HASH:=skip

PKG_BUILD_DIR:=$(BUILD_DIR)/xray-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Download/xray
	FILE:=$(PKG_SOURCE)
	URL:=$(PKG_SOURCE_URL)
	HASH:=skip
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	unzip -o $(DL_DIR)/$(PKG_SOURCE) -d $(PKG_BUILD_DIR)
	chmod +x $(PKG_BUILD_DIR)/xray
endef

define Build/Configure
endef

define Build/Compile
	@echo "Using prebuilt Xray binary"
	# 可选：使用 UPX 进一步压缩（如果编译环境有 UPX）
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing with UPX..."; \
		upx --best --lzma $(PKG_BUILD_DIR)/xray || upx -9 $(PKG_BUILD_DIR)/xray || true; \
	else \
		echo "UPX not found, skipping compression"; \
	fi
endef

$(eval $(call BuildPackage,xray))

romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xray $(ROMFSDIR)/usr/bin/xray
