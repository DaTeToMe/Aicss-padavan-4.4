include $(ROOTDIR)/rules.mk

PKG_NAME:=sqlite
PKG_VERSION:=3490100

PKG_SOURCE:=$(PKG_NAME)-autoconf-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://www.sqlite.org/2025/
PKG_HASH:=106642d8ccb36c5f7323b64e4152e9b719f7c0215acf5bfeac3d5e7f97b59254

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-autoconf-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

CONFIGURE_ARGS += \
	$(if $(LIBS_BUILD_SHARED),--disable-static,--enable-static) \
	$(if $(LIBS_BUILD_SHARED),--enable-shared,--disable-shared) \
	--disable-readline \
	--disable-dynamic-extensions \
	--disable-fts3 \
	--disable-fts4 \
	--disable-fts5 \
	--disable-json1 \
	--disable-rtree \
	--disable-session \
	--disable-debug \
	--disable-static-shell

$(eval $(call BuildPackage,sqlite))

romfs:
	$(INSTALL_DIR) $(ROMFSDIR)/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libsqlite3.so* $(ROMFSDIR)/lib/
