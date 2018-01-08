PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=bf13357b244de431379f253303a9c5c009d9ac14
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
