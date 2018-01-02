PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=027dad39fac4a3172c12895f129fff065e7663f7
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
