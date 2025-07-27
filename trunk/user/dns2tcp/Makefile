include $(ROOTDIR)/rules.mk
PKG_NAME:=dns2tcp-plus
PKG_VERSION:=1.2.0
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ITVAPP/dns2tcp-plus/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=5739db6e43be254c523883513a8ada35cf1c7a5e760aa2d8350a1d68feb08d58
include $(INCLUDE_DIR)/package.mk
$(eval $(call BuildPackage,dns2tcp-plus))
romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns2tcp $(ROMFSDIR)/usr/bin/dns2tcp-plus
	ln -sf dns2tcp-plus $(ROMFSDIR)/usr/bin/dns2tcp
