PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=40a2a9a5d8da2ac5e70e688bf62b2f6b10e26f19
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
