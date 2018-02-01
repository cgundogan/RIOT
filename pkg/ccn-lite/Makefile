PKG_NAME=ccn-lite
PKG_URL=https://github.com/cgundogan/ccn-lite/
PKG_VERSION=7d8e8df4d9f93d6f20ee65a2f78d6677d25d9389
PKG_LICENSE=ISC

.PHONY: all

export RIOT_CFLAGS = ${CFLAGS} ${INCLUDES}

all: git-download
	cd $(PKG_BUILDDIR)/src && cmake -DCCNL_RIOT=1 -DRIOT_CFLAGS="${RIOT_CFLAGS}" . && make
	cp $(PKG_BUILDDIR)/src/lib/libccnl-riot.a ${BINDIR}/ccn-lite.a

include $(RIOTBASE)/pkg/pkg.mk
