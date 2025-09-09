include $(ROOTDIR)/rules.mk
PKG_NAME:=dns2tcp-plus
PKG_VERSION:=1.3.1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ITVAPP/dns2tcp-plus/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=4706f2cfae496032e2d23473a0af4a3270f86e1bf431a8881e010fcc3fd2c80f
include $(INCLUDE_DIR)/package.mk
$(eval $(call BuildPackage,dns2tcp-plus))
romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns2tcp-plus $(ROMFSDIR)/usr/bin/dns2tcp-plus
	ln -sf dns2tcp-plus $(ROMFSDIR)/usr/bin/dns2tcp
