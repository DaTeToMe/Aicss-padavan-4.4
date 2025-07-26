include $(ROOTDIR)/rules.mk
PKG_NAME:=dns2tcp-plus
PKG_VERSION:=1.2.0
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ITVAPP/dns2tcp-plus/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=0a5f425d6b870c69b34e7efde09342604b500d62c1df36425428ef9493e624c8
include $(INCLUDE_DIR)/package.mk
$(eval $(call BuildPackage,dns2tcp-plus))
romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns2tcp $(ROMFSDIR)/usr/bin/dns2tcp-plus
