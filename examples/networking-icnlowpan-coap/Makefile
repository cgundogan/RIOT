# Default Makefile, for host native GNRC-based networking

# name of your application
APPLICATION = gcoap_example

# If no BOARD is found in the environment, use this default:
BOARD ?= samr21-xpro

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

BOARD_INSUFFICIENT_MEMORY := arduino-duemilanove arduino-mega2560 arduino-uno \
                             chronos mega-xplained msb-430 msb-430h \
                             nucleo-f031k6 nucleo-f042k6 nucleo-l031k6 \
                             nucleo-f030r8 nucleo-f303k8 nucleo-f334r8 \
                             nucleo-l053r8 stm32f0discovery telosb \
                             waspmote-pro wsn430-v1_3b wsn430-v1_4 z1

## Uncomment to redefine port, for example use 61616 for RFC 6282 UDP compression.
#GCOAP_PORT = 5683
#CFLAGS += -DGCOAP_PORT=$(GCOAP_PORT)

## Uncomment to redefine request token length, max 8.
#GCOAP_TOKENLEN = 2
#CFLAGS += -DGCOAP_TOKENLEN=$(GCOAP_TOKENLEN)

CFLAGS += -DIEEE802154_DEFAULT_PANID=0x15
CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=15
CFLAGS += -DGNRC_IPV6_NIB_CONF_NO_RTR_SOL
CFLAGS += -DDEBUG_ASSERT_VERBOSE

#CFLAGS += -DGNRC_NETIF_IPV6_ADDRS_NUMOF=10 \
#          -DGNRC_NETIF_IPV6_GROUPS_NUMOF=5 -DGNRC_IPV6_NIB_NUMOF=12 \
#          -DGNRC_IPV6_NIB_OFFL_NUMOF=5 # be able to configure at least one route

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6_router_default
USEMODULE += gcoap
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gnrc_ipv6
USEMODULE += sixlowpan

# Required by gcoap example
USEMODULE += od
USEMODULE += fmt
# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps
USEMODULE += netstats_l2
USEMODULE += gnrc_sixlowpan_iphc_nhc

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
