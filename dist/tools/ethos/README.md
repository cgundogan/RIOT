To use, add

    #
    GNRC_NETIF_NUMOF := 2
    USEMODULE += eth_over_serial gnrc_netdev2
    CFLAGS += '-DETH_OVER_SERIAL_UART=UART_DEV(1)' -DETH_OVER_SERIAL_BAUDRATE=115200

to app Makefile, then run this tool like this:
    # sudo ./eth_over_serial <tap-device> <serial>
