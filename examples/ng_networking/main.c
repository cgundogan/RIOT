/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "shell.h"
#include "board_uart0.h"
#include "posix_io.h"

#include <net/hncp.h>
#include <net/dncp.h>

#include "net/ng_nettype.h"

static char _stack[HNCP_STACKSIZE_DEFAULT];

extern int udp_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    shell_t shell;

    puts("RIOT network stack example application");

    hncp_init(NG_NETTYPE_UDP, 1337, _stack, sizeof(_stack), HNCP_PRIO_DEFAULT);

    /* start shell */
    puts("All up, running the shell now");
    posix_open(uart0_handler_pid, 0);
    shell_init(&shell, shell_commands, UART0_BUFSIZE, uart0_readc, uart0_putc);
    shell_run(&shell);

    /* should be never reached */
    return 0;
}
