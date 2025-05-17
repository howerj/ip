CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99 -Wno-unused-function
LDFLAGS=-lpcap
TARGET=ip
#INTERFACE=tap0
INTERFACE=lo
IP=127.0.0.1
#GATE=127.0.0.1
#IP=192.168.1.40
#GATE=192.168.1.254
MASK=255.255.255.0
#MAC=C0:11:11:11:11:11
MAC=00:00:00:00:00:00

.PHONY: all default test run clean

all default: ${TARGET}

test run: ${TARGET}
	sudo ./${TARGET} -vvv -o interface=${INTERFACE} -o ip=${IP} -o mac=${MAC}

${TARGET}: ip.c ip.h makefile
	${CC} ${CFLAGS} $< -o $@ ${LDFLAGS}

clean:
	git clean -dffx
