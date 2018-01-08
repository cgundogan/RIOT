PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=530c398992ae28e592e337914e5bdee282fe6d0d
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
