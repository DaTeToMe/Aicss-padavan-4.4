include $(ROOTDIR)/rules.mk
PKG_NAME:=dns2tcp-plus
PKG_VERSION:=1.3.0
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ITVAPP/dns2tcp-plus/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=71c7425a001122161411637926bb0574df379254361e07341060ae765b445df2
include $(INCLUDE_DIR)/package.mk
$(eval $(call BuildPackage,dns2tcp-plus))
romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns2tcp-plus $(ROMFSDIR)/usr/bin/dns2tcp-plus
	ln -sf dns2tcp-plus $(ROMFSDIR)/usr/bin/dns2tcp
