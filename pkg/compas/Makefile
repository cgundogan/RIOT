PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=8475eb94df981f41d68cc91251f8ba6623dba8ac
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
