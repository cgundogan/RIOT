#!/bin/bash -ex

SERIAL=""
PORT=""

if [ $1 == "CONSUMER" ]; then
	SERIAL=ATML2127031800004590
elif [ $1 == "PRODUCER" ]; then
	SERIAL=ATML2127031800008430
fi

PORT=$(make list-ttys | sed -n "s/.*serial: '${SERIAL}', tty(s): \(.*\)/\1/p")
if [ -n "${PORT}" ]; then
	CFLAGS="-DNODE_${1}" make clean all flash term SERIAL="${SERIAL}" PORT=/dev/"${PORT}"
fi
