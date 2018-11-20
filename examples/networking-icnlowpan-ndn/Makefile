APPLICATION = networking-icnlowpan-ndn

# If no BOARD is found in the environment, use this default:
BOARD ?= samr21-xpro

BOARD_WHITELIST := fox iotlab-m3 msba2 mulle native pba-d-01-kw2x samr21-xpro


# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

CFLAGS += -DUSE_LINKLAYER
CFLAGS += -DUSE_RONR
CFLAGS += -DCCNL_UAPI_H_
CFLAGS += -DUSE_SUITE_NDNTLV
CFLAGS += -DNEEDS_PREFIX_MATCHING
CFLAGS += -DNEEDS_PACKET_CRAFTING
CFLAGS += -DIEEE802154_DEFAULT_PANID=0x15
CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=15
#CFLAGS += -DDEBUG_ASSERT_VERBOSE
CFLAGS += -DCCNL_MAX_PACKET_SIZE=256
CFLAGS += -DCCNL_MAX_PREFIX_SIZE=128
CFLAGS += -DCCNL_CACHE_SIZE=5
CFLAGS += -DCCNL_MAX_INTEREST_RETRANSMIT=0
#CFLAGS += -DMAX_REQS=1000U
#CFLAGS += -DICNL_PREFIX_CUT="0x08,0x03,'H','A','W',0x08,0x03,'B','T','7',0x08,0x04,'R','o','o','m',0x00"
#CFLAGS += -DICNL_PREFIX_CUT_LEN=16

#CFLAGS_OPT := -O0

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

ICNL_DISABLE ?= 0

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# This application dumps received packets to STDIO using the pktdump module
#USEMODULE += gnrc_pktdump
USEMODULE += prng_xorshift
USEMODULE += netstats_l2
USEMODULE += gnrc_sixlowpan_frag
#USEMODULE += gnrc_sixlowpan

USEPKG += ccn-lite

include $(RIOTBASE)/Makefile.include
