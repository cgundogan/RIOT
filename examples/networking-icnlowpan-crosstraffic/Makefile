APPLICATION = crosstraffic

BOARD ?= samr21-xpro

RIOTBASE ?= $(CURDIR)/../..

CFLAGS += -DIEEE802154_DEFAULT_PANID=0x15
CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=15
CFLAGS += -DGNRC_IPV6_NIB_CONF_NO_RTR_SOL
CFLAGS += -DDEBUG_ASSERT_VERBOSE

USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6_router_default
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gnrc_ipv6
USEMODULE += gnrc_udp
USEMODULE += sixlowpan

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps
USEMODULE += netstats_l2
USEMODULE += gnrc_sixlowpan_iphc_nhc

DEVELHELP ?= 1

QUIET ?= 1

include $(RIOTBASE)/Makefile.include
