PKG_NAME=ccn-lite
PKG_URL=https://github.com/cgundogan/ccn-lite/
PKG_VERSION=f3f71c50768f935375169c13269d7d6b29a5dc93
PKG_LICENSE=ISC

.PHONY: all

export RIOT_CFLAGS = $(CFLAGS) $(INCLUDES)

TOOLCHAIN_FILE=$(PKG_BUILDDIR)/xcompile-toolchain.cmake

all: $(PKG_BUILDDIR)/src/Makefile
	$(MAKE) -C $(PKG_BUILDDIR)/src && \
	cp $(PKG_BUILDDIR)/src/lib/libccnl-riot.a ${BINDIR}/ccn-lite.a

$(PKG_BUILDDIR)/src/Makefile: $(TOOLCHAIN_FILE)
	cd $(PKG_BUILDDIR)/src && \
	cmake -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
		  -DCCNL_RIOT=1 -DRIOT_CFLAGS="${RIOT_CFLAGS}" -DBUILD_TESTING=OFF .

$(TOOLCHAIN_FILE): git-download
	$(RIOTBASE)/dist/tools/cmake/generate-xcompile-toolchain.sh > $(TOOLCHAIN_FILE)

include $(RIOTBASE)/pkg/pkg.mk
