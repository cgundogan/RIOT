PKG_NAME=tinydtls
PKG_URL=https://git.eclipse.org/r/tinydtls/org.eclipse.tinydtls
PKG_VERSION=f5953d1d473bf239922fc91613ec55250a97377d
PKG_LICENSE=EPL-1.0,EDL-1.0

CFLAGS += -Wno-implicit-fallthrough
# following is require due to known issue with newlib 2.4.x, see bug report:
# http://lists-archives.com/cygwin/97008-gettimeofday-not-defined.html
CFLAGS += -D_XOPEN_SOURCE=600

.PHONY: all

DTLS_PATH := /media/Data/org.eclipse.tinydtls
all: git-download
	rm -rf $(PKG_BUILDDIR) && mkdir -p $(PKG_BUILDDIR)
	cd $(DTLS_PATH) && git checkout $(PKG_VERSION)
	rsync -a $(DTLS_PATH)/ $(dir $(PKG_BUILDDIR)/tinydtls) --exclude='.git/'
	@cp $(PKG_BUILDDIR)/Makefile.riot $(PKG_BUILDDIR)/Makefile
	@cp $(PKG_BUILDDIR)/aes/Makefile.riot $(PKG_BUILDDIR)/aes/Makefile
	@cp $(PKG_BUILDDIR)/ecc/Makefile.riot $(PKG_BUILDDIR)/ecc/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)



include $(RIOTBASE)/pkg/pkg.mk

ifeq (llvm,$(TOOLCHAIN))
  CFLAGS += -Wno-format-nonliteral
endif
