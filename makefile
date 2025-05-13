CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99 -Wno-unused-function
LDFLAGS=-lpcap
TARGET=ip
INTERFACE=lo

.PHONY: all default test run clean

all default: ${TARGET}

test run: ${TARGET}
	sudo ./${TARGET} -vvv -o interface=${INTERFACE}

${TARGET}: ip.c ip.h makefile
	${CC} ${CFLAGS} $< -o $@ ${LDFLAGS}

clean:
	git clean -dffx
