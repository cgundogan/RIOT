PKG_NAME=ccn-lite
PKG_URL=https://github.com/cgundogan/ccn-lite/
PKG_VERSION=
PKG_LICENSE=ISC

.PHONY: all

export RIOT_CFLAGS = ${CFLAGS} ${INCLUDES}

all:
	rm -rf $(PKG_BUILDDIR)
	git clone --depth=1 -b compas $(PKG_URL) $(PKG_BUILDDIR)
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite.a
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite-utils.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite.a ${BINDIR}/ccn-lite.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite-utils.a ${BINDIR}/ccn-lite-utils.a

include $(RIOTBASE)/pkg/pkg.mk
