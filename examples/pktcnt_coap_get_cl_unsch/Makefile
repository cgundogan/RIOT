# name of your application
APPLICATION = pktcnt_coap_get_cl_unsch

# If no BOARD is found in the environment, use this default:
BOARD ?= iotlab-m3

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

BOARD_INSUFFICIENT_MEMORY := airfy-beacon b-l072z-lrwan1 bluepill calliope-mini \
                             cc2650-launchpad cc2650stk maple-mini \
                             microbit msb-430 msb-430h nrf51dongle nrf6310 \
                             nucleo32-f031 nucleo32-f042 nucleo32-f303 nucleo32-l031 \
                             nucleo-f030 nucleo-f070 nucleo-f072 nucleo-f103 nucleo-f302 \
                             nucleo-f334 nucleo-l053 nucleo-l073 opencm904 \
                             spark-core stm32f0discovery telosb weio wsn430-v1_3b \
                             wsn430-v1_4 yunjia-nrf51822 z1

# The following boards do not have an available UART
BOARD_BLACKLIST += mips-malta pic32-wifire pic32-clicker ruuvitag thingy52

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for 6LoWPAN border router
USEMODULE += gnrc_ipv6_router_default
# Add forwarding table
USEMODULE += fib
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps
USEMODULE += pktcnt
# Add a routing protocol
USEMODULE += gcoap
USEMODULE += od
USEMODULE += gnrc_rpl
USEMODULE += auto_init_gnrc_rpl

# include UHCP client
USEMODULE += gnrc_uhcpc

# Optionally include RPL as a routing protocol. When includede gnrc_uhcpc will
# configure the node as a RPL DODAG root when receiving a prefix.
#USEMODULE += gnrc_rpl

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

ifneq (,$(I3_CONFIRMABLE))
  CFLAGS += -DI3_CONFIRMABLE
  CFLAGS += -DGCOAP_RESEND_BUFS_MAX=120
endif
ifneq (,$(DAO_INT))
  CFLAGS += -DGNRC_RPL_REGULAR_DAO_INTERVAL=$(DAO_INT)
else
  CFLAGS += -DGNRC_RPL_REGULAR_DAO_INTERVAL=5
endif
CFLAGS += -DLOG_LEVEL=LOG_NONE
CFLAGS += -DGNRC_IPV6_NIB_NUMOF=64
CFLAGS += -DGNRC_IPV6_NIB_OFFL_NUMOF=64
CFLAGS += -DGCOAP_NON_TIMEOUT=2000000
CFLAGS += -DGCOAP_REQ_WAITING_MAX=125
CFLAGS += -DGCOAP_STACK_SIZE=1536
CFLAGS += -DGCOAP_MSG_QUEUE_SIZE=32
CFLAGS += -D_NETIF_NETAPI_MSG_QUEUE_SIZE=32

include $(RIOTBASE)/Makefile.include

.PHONY: host-tools

host-tools:
	$(Q)env -u CC -u CFLAGS make -C $(RIOTBASE)/dist/tools

# Set a custom channel if needed
ifneq (,$(filter cc110x,$(USEMODULE)))          # radio is cc110x sub-GHz
  DEFAULT_CHANNEL ?= 0
  CFLAGS += -DCC110X_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
else
  ifneq (,$(filter at86rf212b,$(USEMODULE)))    # radio is IEEE 802.15.4 sub-GHz
    DEFAULT_CHANNEL ?= 5
    CFLAGS += -DIEEE802154_DEFAULT_SUBGHZ_CHANNEL=$(DEFAULT_CHANNEL)
  else                                          # radio is IEEE 802.15.4 2.4 GHz
    DEFAULT_CHANNEL ?= 11
    CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
  endif
endif
