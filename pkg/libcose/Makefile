PKG_NAME=libcose
PKG_URL=https://github.com/chrysn-pull-requests/libcose
PKG_VERSION=f4eb5b54c48a2985512bf9e83587bf7b2ec90fb4
PKG_LICENSE=LGPL

include $(RIOTBASE)/pkg/pkg.mk

all:
	"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)
	"$(MAKE)" -C $(PKG_SOURCE_DIR)/src/crypt -f $(CURDIR)/Makefile.$(PKG_NAME)_crypt
