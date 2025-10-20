THISDIR = $(shell pwd)
SRC_SS_NAME=shadowsocks-libev-3.3.5

all:
	@echo "Skipping shadowsocks binary compilation, only installing management interface"

clean:
	@echo "Nothing to clean"
	
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
endif
