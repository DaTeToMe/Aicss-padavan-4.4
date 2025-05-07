include $(ROOTDIR)/rules.mk

PKG_NAME:=msd_lite
PKG_SOURCE_DATE:=2025-03-16

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/rozhuk-im/msd_lite
PKG_SOURCE_VERSION:=0e1e33d03f820b716ea52dd692ee0bf222c60d28

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

$(eval $(call BuildPackage,msd_lite))

romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/msd_lite $(ROMFSDIR)/usr/bin/msd_lite
	$(INSTALL_DIR) $(ROMFSDIR)/etc_ro
	$(INSTALL_CONF) ./msd_lite.conf $(ROMFSDIR)/etc_ro/msd_lite.conf
