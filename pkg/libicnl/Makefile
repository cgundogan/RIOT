PKG_NAME=libICNL
PKG_URL=https://github.com/cgundogan/libICNL/
PKG_VERSION=80f073f8668e8fb9f97ac3bb370082cfe7ff8a22
PKG_LICENSE=LGPLv2.1

.PHONY: all

all: git-download
	git -C $(PKG_BUILDDIR) submodule update --init --recursive
	cd $(PKG_BUILDDIR)/build && CFLAGS="$(CFLAGS)" cmake -DBUILD_TESTING=OFF .. && make && \
	cd lib && for l in *.a; do $(AR) x $$l; done && ar rcs libicnl.a *.obj
	cp $(PKG_BUILDDIR)/build/lib/libicnl.a $(BINDIR)/

include $(RIOTBASE)/pkg/pkg.mk
