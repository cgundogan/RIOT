PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=2d1a586ea63866abc4ec463a8cc0b171676f849c
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
