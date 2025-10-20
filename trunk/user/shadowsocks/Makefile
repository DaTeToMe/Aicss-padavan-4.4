THISDIR = $(shell pwd)
SRC_SS_NAME=shadowsocks-libev-3.3.5

all: extract_test config_test
	$(MAKE) -j$(HOST_NCPU) -C $(SRC_SS_NAME)

extract_test: extract_ss_test

extract_ss_test:
	( if [ ! -d $(SRC_SS_NAME) ]; then \
		tar xf $(SRC_SS_NAME).tar.gz ; \
	fi )

config_test: config_ss

config_ss:
	( if [ -f ./ss_config_done ]; then \
		echo "the same configuration"; \
	else \
		make configure_ss && touch ss_config_done; \
	fi )

configure_ss:
	( cd $(SRC_SS_NAME) ; \
	ac_cv_prog_PCRE_CONFIG="$(STAGEDIR)/bin/pcre-config" \
	./configure \
		--prefix=/usr \
		--disable-documentation \
		--disable-ssp \
		--disable-assert \
		--host=$(HOST_TARGET) \
		--build=$(HOST_BUILD) ; \
	)

clean: clean_ss
	rm -f ss_config_done

clean_ss:
	( if [ -f $(SRC_SS_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_SS_NAME) distclean ; \
	fi )
	
romfs:
ifeq ($(CONFIG_FIRMWARE_INCLUDE_SHADOWSOCKS),y)
	chmod -R +x scripts/
	$(ROMFSINST) $(THISDIR)/scripts/ /usr/bin/
	$(ROMFSINST) $(THISDIR)/oversea/oversea_list.conf /etc_ro/oversea_list.conf
	$(ROMFSINST) $(THISDIR)/gfwlist/gfwlist_list.conf /etc_ro/gfwlist_list.conf
	$(ROMFSINST) /etc_ro/ss_dom.sh
	$(ROMFSINST) /etc_ro/uss_dom.sh
	$(ROMFSINST) /etc_ro/ss_ip.sh
	$(ROMFSINST) /etc_ro/ss_lan_bip.sh
	$(ROMFSINST) /etc_ro/ss_lan_gmip.sh
	$(ROMFSINST) /etc_ro/ss_lan_ip.sh
	$(ROMFSINST) /etc_ro/ss_wan_ip.sh
	$(ROMFSINST) /etc_ro/ss_dlink.sh
	$(ROMFSINST) $(THISDIR)/ss/ /etc_ro/ss/
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_SS_NAME)/src/ss-redir /usr/bin/ss-redir
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_SS_NAME)/src/ss-local /usr/bin/ss-local
endif
ifeq ($(CONFIG_FIRMWARE_INCLUDE_SSSERVER),y)
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_SS_NAME)/src/ss-server /usr/bin/ss-server
endif
ifeq ($(CONFIG_FIRMWARE_INCLUDE_SSV2RP),y)
	$(ROMFSINST) -p +x $(THISDIR)/v2ray-plugin /usr/bin/v2ray-plugin
endif
