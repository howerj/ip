# See <https://github.com/howerj/ip>
CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99 -Wno-unused-function
LDFLAGS=-lpcap
TARGET=ip
INTERFACE=lo
IP=127.0.0.1
MASK=255.255.255.0
MAC=00:00:00:00:00:00

.PHONY: all default test run clean

all default: ${TARGET}

# You are best running the script in `setup`, the default options here are not
# the best.
test run: ${TARGET}
	sudo ./${TARGET} -vvv -o interface=${INTERFACE} -o ip=${IP} -o mac=${MAC}

${TARGET}: ip.c ip.h makefile
	${CC} ${CFLAGS} $< -o $@ ${LDFLAGS}

clean:
	git clean -dffx
