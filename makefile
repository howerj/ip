CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99 -Wno-unused-function
LDFLAGS=-lpcap
TARGET=ip

.PHONY: all default test run clean

all default: ${TARGET}

test run: ${TARGET}
	./${TARGET}

${TARGET}: ip.c ip.h makefile
	${CC} ${CFLAGS} $< -o $@ ${LDFLAGS}

clean:
	git clean -dffx
