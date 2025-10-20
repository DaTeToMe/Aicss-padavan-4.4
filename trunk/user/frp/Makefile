THISDIR := $(shell pwd)

all: extra_test compress
	@echo "frp build done!"

extra_test:
	( if [ ! -f frpc ]; then \
		echo "Error: frpc not found in current directory"; \
		exit 1; \
	fi )

# 可选的 UPX 压缩步骤
compress: extra_test
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing frpc with UPX..."; \
		if [ ! -f frpc.original ]; then \
			cp frpc frpc.original; \
		fi; \
		upx --best --lzma frpc || upx -9 frpc || echo "UPX compression failed, using original binary"; \
		echo "UPX compression done"; \
	else \
		echo "UPX not found, skipping compression"; \
	fi

clean:
	@if [ -f frpc.original ]; then \
		mv frpc.original frpc; \
		echo "Restored original frpc binary"; \
	fi
	#rm -rf frpc

romfs:
ifeq ($(CONFIG_FIRMWARE_INCLUDE_FRPC),y)
	$(ROMFSINST) -p +x $(THISDIR)/frpc /usr/bin/frpc
endif
	$(ROMFSINST) -p +x $(THISDIR)/frp.sh /usr/bin/frp.sh
	$(ROMFSINST) /etc_ro/frp_script.sh
