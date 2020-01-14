PKG_NAME=libcose
PKG_URL=https://github.com/chrysn-pull-requests/libcose
PKG_VERSION=d65716eb806852a741a37dbe0c1bb80eebca25c4
PKG_LICENSE=LGPL

include $(RIOTBASE)/pkg/pkg.mk

all:
	"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)
	"$(MAKE)" -C $(PKG_SOURCE_DIR)/src/crypt -f $(CURDIR)/Makefile.$(PKG_NAME)_crypt
