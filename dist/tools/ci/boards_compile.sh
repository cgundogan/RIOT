#!/usr/bin/env bash
#
# Copyright (C) 2016 HAW Hamburg
#
# This file is subject to the terms and conditions of the GNU Lesser
# General Public License v2.1. See the file LICENSE in the top level
# directory for more details.
#

RIOT_BOARD=${RIOT_BOARD:-native}
RIOTBASE=${RIOTBASE:-.}
NPROC=${NPROC:-8}

for app in ${RIOTBASE}/{examples,tests}/*; do
    if [ -d ${app} ]; then
        if [[ $(make -sC $app info-boards-supported | tr ' ' '\n' | sed -n "/^${RIOT_BOARD}$/p") ]]; then
            echo -n "Building ${app} for board ${RIOT_BOARD}: "
            make -j ${NPROC} -sC $app clean all BOARD=${RIOT_BOARD} > /dev/null
            if (($? > 0)); then
                echo "failed!"
            else
                echo "success!"
            fi
        fi
    fi
done
