PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=8c71c5b0f85a749f46ac1cd408bc94dded697982
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
